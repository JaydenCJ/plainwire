//! Annotated hex dump: the raw bytes in the classic `offset | hex | ascii`
//! layout, with a fourth column naming the structural region each row falls in
//! (start-line, a specific header, a chunk size or its data, the body). This is
//! the byte-level counterpart to [`crate::annotate`] — the same message, one
//! zoom level closer.

use crate::message::Message;

const WIDTH: usize = 16;

/// Name the structural region that byte `offset` belongs to.
fn region_at(m: &Message, offset: usize) -> String {
    if offset < m.body_start {
        if m.start_line.span.contains(offset) {
            return "start-line".to_string();
        }
        for (i, h) in m.headers.iter().enumerate() {
            if h.line_span.contains(offset) {
                return format!("header[{i}]");
            }
        }
        return "crlf".to_string();
    }
    for (i, c) in m.body.chunks.iter().enumerate() {
        if c.size_span.contains(offset) {
            return format!("chunk[{i}].size");
        }
        if c.data_span.contains(offset) {
            return format!("chunk[{i}].data");
        }
    }
    if offset < m.body.span.end {
        return "body".to_string();
    }
    "trailing".to_string()
}

/// Render `buf` as an annotated hex dump against the structure of `m`.
pub fn render(m: &Message, buf: &[u8]) -> String {
    let mut out = String::new();
    out.push_str(
        "offset    hex                                              ascii             region\n",
    );
    if buf.is_empty() {
        out.push_str("(empty input)\n");
        return out;
    }
    let mut off = 0;
    while off < buf.len() {
        let row = &buf[off..(off + WIDTH).min(buf.len())];
        let mut hex = String::with_capacity(WIDTH * 3);
        let mut ascii = String::with_capacity(WIDTH);
        for &b in row {
            hex.push_str(&format!("{b:02x} "));
            ascii.push(if (0x20..=0x7e).contains(&b) {
                b as char
            } else {
                '.'
            });
        }
        // Pad the hex column to a fixed width so ascii/region line up.
        let hex = format!("{hex:<width$}", width = WIDTH * 3);
        out.push_str(&format!(
            "{off:08x}  {hex} {ascii:<width$}  {region}\n",
            width = WIDTH,
            region = region_at(m, off)
        ));
        off += WIDTH;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;
    use crate::message::ParseMode;

    fn dump(raw: &[u8]) -> String {
        let a = analyze(raw, ParseMode::Request);
        render(&a.message, raw)
    }

    #[test]
    fn has_a_header_row() {
        let out = dump(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(out.starts_with("offset    hex"));
        assert!(out.contains("region"));
    }

    #[test]
    fn first_row_offset_is_zero_and_labelled_start_line() {
        let out = dump(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        let first = out.lines().nth(1).unwrap();
        assert!(first.starts_with("00000000"));
        assert!(first.ends_with("start-line"));
    }

    #[test]
    fn ascii_column_shows_printable_bytes() {
        let out = dump(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        // "GET / HTTP/1.1" is printable; the CR/LF become dots.
        assert!(out.contains("GET / HTTP/1.1.."));
    }

    #[test]
    fn body_bytes_are_labelled_body_region() {
        // A Content-Length body may not begin on a 16-byte boundary, so the
        // body label attaches to whichever row starts inside the body region.
        let out = dump(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 40\r\n\r\n0123456789012345678901234567890123456789");
        assert!(out.lines().any(|l| l.ends_with("body")));
    }

    #[test]
    fn chunk_regions_are_labelled() {
        // A 0x20 = 32-byte chunk guarantees a row begins inside the chunk data.
        let body = b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n20\r\n01234567012345670123456701234567\r\n0\r\n\r\n";
        let out = dump(body);
        assert!(out.contains("chunk[0].data"), "no chunk label in:\n{out}");
    }
}
