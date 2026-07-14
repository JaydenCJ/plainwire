//! Chunked transfer-coding analysis.
//!
//! [`scan_chunks`] walks a chunked body from `start`, parsing each
//! `chunk-size [ ";" ext ] CRLF chunk-data CRLF` up to the terminating
//! `0 CRLF ... CRLF`. It records each [`Chunk`]'s spans and reports malformed
//! sizes (`PW011`), chunk extensions (`PW012`), a truncated body (`PW018`) and
//! a missing terminator (`PW020`). It reuses the parser's line reader so bare
//! LF terminators inside the body are handled the same way as in the header
//! block.

use crate::findings::Finding;
use crate::message::Chunk;
use crate::parser::read_line;
use crate::span::Span;

/// The outcome of scanning a chunked body.
#[derive(Debug, Clone)]
pub struct ChunkScan {
    pub chunks: Vec<Chunk>,
    /// Sum of decoded chunk sizes.
    pub decoded_len: usize,
    /// Whether the terminating 0-size chunk was seen.
    pub complete: bool,
    /// Offset just past the terminator (and any trailer section).
    pub end: usize,
    /// Number of trailer header lines after the final chunk.
    pub trailer_count: usize,
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let mut s = 0;
    let mut e = bytes.len();
    while s < e && (bytes[s] == b' ' || bytes[s] == b'\t') {
        s += 1;
    }
    while e > s && (bytes[e - 1] == b' ' || bytes[e - 1] == b'\t') {
        e -= 1;
    }
    &bytes[s..e]
}

fn parse_hex_size(bytes: &[u8]) -> Option<usize> {
    if bytes.is_empty() || !bytes.iter().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let s = std::str::from_utf8(bytes).ok()?;
    usize::from_str_radix(s, 16).ok()
}

/// Scan a chunked body beginning at byte `start`.
pub fn scan_chunks(buf: &[u8], start: usize, findings: &mut Vec<Finding>) -> ChunkScan {
    let mut chunks = Vec::new();
    let mut decoded = 0usize;
    let mut complete = false;
    let mut trailer_count = 0usize;
    let mut pos = start;

    loop {
        if pos >= buf.len() {
            break;
        }
        let size_line = read_line(buf, pos);
        let cbytes = size_line.content.slice(buf);
        if cbytes.is_empty() {
            findings.push(Finding::new(
                "PW011",
                "expected a chunk size but found a blank line".to_string(),
                Some(size_line.content),
            ));
            pos = size_line.full.end;
            break;
        }

        let (size_part, extension) = match cbytes.iter().position(|&b| b == b';') {
            Some(i) => (&cbytes[..i], Some(trim_string(&cbytes[i + 1..]))),
            None => (cbytes, None),
        };

        let Some(size) = parse_hex_size(trim_ows(size_part)) else {
            findings.push(Finding::new(
                "PW011",
                format!(
                    "chunk size `{}` is not a hexadecimal number",
                    trim_string(size_part)
                ),
                Some(size_line.content),
            ));
            pos = size_line.full.end;
            break;
        };

        if let Some(ext) = &extension {
            findings.push(Finding::new(
                "PW012",
                format!("chunk carries an extension `;{ext}`"),
                Some(size_line.content),
            ));
        }

        if size == 0 {
            // Terminating chunk. Consume any trailer fields up to the blank line.
            complete = true;
            pos = size_line.full.end;
            loop {
                if pos >= buf.len() {
                    break;
                }
                let tl = read_line(buf, pos);
                pos = tl.full.end;
                if tl.content.is_empty() {
                    break;
                }
                trailer_count += 1;
            }
            break;
        }

        let data_start = size_line.full.end;
        let data_end = data_start + size;
        if data_end > buf.len() {
            let avail = buf.len().saturating_sub(data_start);
            findings.push(Finding::new(
                "PW018",
                format!("chunk declares {size} byte(s) but only {avail} are present"),
                Some(size_line.content),
            ));
            chunks.push(Chunk {
                size,
                size_span: size_line.content,
                data_span: Span::new(data_start, buf.len()),
                extension,
            });
            decoded += avail;
            break;
        }

        chunks.push(Chunk {
            size,
            size_span: size_line.content,
            data_span: Span::new(data_start, data_end),
            extension,
        });
        decoded += size;

        // The data must be followed by its own CRLF (an empty line).
        let after = read_line(buf, data_end);
        if !after.content.is_empty() {
            findings.push(Finding::new(
                "PW011",
                "chunk data is not followed by CRLF (declared size is misaligned)".to_string(),
                Some(Span::new(data_end, after.content.end)),
            ));
            break;
        }
        pos = after.full.end;
    }

    if !complete {
        findings.push(Finding::new(
            "PW020",
            "chunked body never reached the terminating 0-size chunk".to_string(),
            Some(Span::new(start.min(buf.len()), buf.len())),
        ));
    }

    ChunkScan {
        chunks,
        decoded_len: decoded,
        complete,
        end: pos,
        trailer_count,
    }
}

fn trim_string(bytes: &[u8]) -> String {
    String::from_utf8_lossy(trim_ows(bytes)).into_owned()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scan(buf: &[u8]) -> (ChunkScan, Vec<Finding>) {
        let mut f = Vec::new();
        let s = scan_chunks(buf, 0, &mut f);
        (s, f)
    }

    fn codes(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.code).collect()
    }

    #[test]
    fn single_chunk_then_terminator() {
        let (s, f) = scan(b"5\r\nhello\r\n0\r\n\r\n");
        assert!(s.complete);
        assert_eq!(s.chunks.len(), 1);
        assert_eq!(s.chunks[0].size, 5);
        assert_eq!(s.decoded_len, 5);
        assert_eq!(
            s.chunks[0].data_span.slice(b"5\r\nhello\r\n0\r\n\r\n"),
            b"hello"
        );
        assert!(f.is_empty(), "unexpected findings: {:?}", codes(&f));
    }

    #[test]
    fn multiple_chunks_sum_decoded_length() {
        let (s, _) = scan(b"3\r\nabc\r\n2\r\nde\r\n0\r\n\r\n");
        assert_eq!(s.chunks.len(), 2);
        assert_eq!(s.decoded_len, 5);
        assert!(s.complete);
    }

    #[test]
    fn hex_sizes_are_decoded() {
        // 0x1a = 26 bytes.
        let body = [
            b"1a\r\n".to_vec(),
            vec![b'x'; 26],
            b"\r\n0\r\n\r\n".to_vec(),
        ]
        .concat();
        let (s, f) = scan(&body);
        assert_eq!(s.chunks[0].size, 26);
        assert!(s.complete);
        assert!(f.is_empty());
    }

    #[test]
    fn chunk_extension_flags_pw012() {
        let (s, f) = scan(b"5;foo=bar\r\nhello\r\n0\r\n\r\n");
        assert!(codes(&f).contains(&"PW012"));
        assert_eq!(s.chunks[0].extension.as_deref(), Some("foo=bar"));
        assert!(s.complete);
    }

    #[test]
    fn non_hex_size_flags_pw011() {
        let (s, f) = scan(b"zz\r\nhello\r\n0\r\n\r\n");
        assert!(codes(&f).contains(&"PW011"));
        assert!(!s.complete);
    }

    #[test]
    fn missing_terminator_flags_pw020() {
        let (s, f) = scan(b"5\r\nhello\r\n");
        assert!(!s.complete);
        assert!(codes(&f).contains(&"PW020"));
    }

    #[test]
    fn truncated_chunk_data_flags_pw018() {
        // Declares 10 bytes but only 3 are present.
        let (s, f) = scan(b"a\r\nabc");
        assert!(codes(&f).contains(&"PW018"));
        assert!(codes(&f).contains(&"PW020"));
        assert!(!s.complete);
        assert_eq!(s.decoded_len, 3);
    }

    #[test]
    fn trailers_after_final_chunk_are_counted() {
        let (s, f) = scan(b"5\r\nhello\r\n0\r\nX-Trace: 1\r\n\r\n");
        assert!(s.complete);
        assert_eq!(s.trailer_count, 1);
        assert!(f.is_empty());
    }

    #[test]
    fn misaligned_data_flags_pw011() {
        // Size says 2 but data run is longer with no CRLF where expected.
        let (_s, f) = scan(b"2\r\nabcdef\r\n0\r\n\r\n");
        assert!(codes(&f).contains(&"PW011"));
    }
}
