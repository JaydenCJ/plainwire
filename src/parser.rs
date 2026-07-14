//! Byte-by-byte HTTP/1.1 message parser.
//!
//! [`parse`] walks the raw buffer one line at a time, recognizing the
//! start-line and the header block, recording an exact [`Span`] for every
//! element and emitting the structural findings (bad line endings, whitespace
//! before a colon, non-token names, obsolete folding, request-line whitespace).
//! It deliberately does **not** decide the body framing — that is
//! [`crate::framing`]'s job, so the two concerns stay independently testable.

use crate::findings::Finding;
use crate::message::{Body, Header, Message, MessageKind, ParseMode, StartLine};
use crate::span::Span;

/// The line terminator that ended a line.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Term {
    /// `\r\n` — the conforming terminator.
    Crlf,
    /// `\n` alone — a desync-relevant bare LF.
    Lf,
    /// End of buffer with no terminator (truncated input).
    None,
}

/// One physical line: the content (without terminator) and the full extent
/// (including terminator) so the caller can advance precisely.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Line {
    pub content: Span,
    pub full: Span,
    pub term: Term,
}

/// Read the line starting at `pos`. A `\r` immediately before the `\n` is taken
/// as part of a CRLF terminator; a lone `\n` is a bare-LF terminator. Any `\r`
/// elsewhere stays inside the content (and is later reported as a bare CR).
pub(crate) fn read_line(buf: &[u8], pos: usize) -> Line {
    let n = buf.len();
    if pos >= n {
        return Line {
            content: Span::empty(pos.min(n)),
            full: Span::empty(pos.min(n)),
            term: Term::None,
        };
    }
    match buf[pos..].iter().position(|&b| b == b'\n') {
        None => Line {
            content: Span::new(pos, n),
            full: Span::new(pos, n),
            term: Term::None,
        },
        Some(off) => {
            let nl = pos + off;
            let full = Span::new(pos, nl + 1);
            if nl > pos && buf[nl - 1] == b'\r' {
                Line {
                    content: Span::new(pos, nl - 1),
                    full,
                    term: Term::Crlf,
                }
            } else {
                Line {
                    content: Span::new(pos, nl),
                    full,
                    term: Term::Lf,
                }
            }
        }
    }
}

/// Whether a byte is a valid RFC 9110 token character (used in field names).
pub(crate) fn is_token_byte(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b)
}

fn trim_ows(bytes: &[u8]) -> &[u8] {
    let mut start = 0;
    let mut end = bytes.len();
    while start < end && (bytes[start] == b' ' || bytes[start] == b'\t') {
        start += 1;
    }
    while end > start && (bytes[end - 1] == b' ' || bytes[end - 1] == b'\t') {
        end -= 1;
    }
    &bytes[start..end]
}

fn lossy(bytes: &[u8]) -> String {
    String::from_utf8_lossy(bytes).into_owned()
}

/// Tracks bare-LF / bare-CR occurrences so they are reported once with a count.
#[derive(Default)]
struct WeirdEndings {
    lf_count: usize,
    lf_first: Option<Span>,
    cr_count: usize,
    cr_first: Option<Span>,
}

impl WeirdEndings {
    fn observe(&mut self, buf: &[u8], line: &Line) {
        if line.term == Term::Lf {
            self.lf_count += 1;
            self.lf_first.get_or_insert(line.full);
        }
        for (i, &b) in line.content.slice(buf).iter().enumerate() {
            if b == b'\r' {
                self.cr_count += 1;
                self.cr_first.get_or_insert(Span::new(
                    line.content.start + i,
                    line.content.start + i + 1,
                ));
            }
        }
    }

    fn emit(self, out: &mut Vec<Finding>) {
        if self.lf_count > 0 {
            out.push(Finding::new(
                "PW008",
                format!(
                    "{} line(s) end with a bare LF instead of CRLF",
                    self.lf_count
                ),
                self.lf_first,
            ));
        }
        if self.cr_count > 0 {
            out.push(Finding::new(
                "PW009",
                format!("{} bare CR byte(s) inside line content", self.cr_count),
                self.cr_first,
            ));
        }
    }
}

/// Parse the start-line and headers of a raw message. Returns the structural
/// [`Message`] (with a placeholder empty body) and the structural findings.
pub fn parse(buf: &[u8], mode: ParseMode) -> (Message, Vec<Finding>) {
    let mut findings = Vec::new();
    let mut weird = WeirdEndings::default();

    // --- start-line ---------------------------------------------------------
    let first = read_line(buf, 0);
    weird.observe(buf, &first);
    let first_bytes = first.content.slice(buf);
    let kind = match mode {
        ParseMode::Request => MessageKind::Request,
        ParseMode::Response => MessageKind::Response,
        ParseMode::Auto => {
            if first_bytes.starts_with(b"HTTP/") {
                MessageKind::Response
            } else {
                MessageKind::Request
            }
        }
    };
    let start_line = parse_start_line(first_bytes, first.content, kind, &mut findings);

    // --- headers ------------------------------------------------------------
    let mut headers: Vec<Header> = Vec::new();
    let mut pos = first.full.end;
    let body_start;
    loop {
        if pos >= buf.len() {
            body_start = buf.len();
            break;
        }
        let line = read_line(buf, pos);
        weird.observe(buf, &line);
        if line.content.is_empty() {
            // Blank line: end of the header block, body follows.
            body_start = line.full.end;
            break;
        }
        let cbytes = line.content.slice(buf);
        let first_byte = cbytes[0];
        if first_byte == b' ' || first_byte == b'\t' {
            // Obsolete line folding: continuation of the previous header.
            fold_onto_previous(&mut headers, &line, cbytes, &mut findings);
            pos = line.full.end;
            continue;
        }
        parse_header_line(&line, cbytes, &mut headers, &mut findings);
        pos = line.full.end;
    }

    weird.emit(&mut findings);

    let message = Message {
        kind,
        start_line,
        headers,
        body: Body::empty(body_start),
        body_start,
        raw_len: buf.len(),
    };
    (message, findings)
}

fn parse_start_line(
    bytes: &[u8],
    span: Span,
    kind: MessageKind,
    findings: &mut Vec<Finding>,
) -> StartLine {
    let s = lossy(bytes);
    let fields = match kind {
        MessageKind::Request => {
            let raw: Vec<&str> = s.split(' ').collect();
            let non_empty: Vec<&str> = raw.iter().filter(|p| !p.is_empty()).copied().collect();
            let irregular = raw.len() != 3 || raw.iter().any(|p| p.is_empty()) || s.contains('\t');
            if irregular {
                findings.push(Finding::new(
                    "PW014",
                    format!(
                        "request line is not exactly `method SP target SP version` ({} space-separated field(s))",
                        raw.len()
                    ),
                    Some(span),
                ));
            }
            let method = non_empty.first().copied().unwrap_or("").to_string();
            let version = if non_empty.len() >= 3 {
                non_empty[non_empty.len() - 1].to_string()
            } else {
                non_empty.get(2).copied().unwrap_or("").to_string()
            };
            // Anything between method and version is the target (spaces in the
            // target are themselves the anomaly flagged above).
            let target = if non_empty.len() >= 3 {
                non_empty[1..non_empty.len() - 1].join(" ")
            } else {
                non_empty.get(1).copied().unwrap_or("").to_string()
            };
            [method, target, version]
        }
        MessageKind::Response => {
            let mut it = s.splitn(3, ' ');
            let version = it.next().unwrap_or("").to_string();
            let status = it.next().unwrap_or("").to_string();
            let reason = it.next().unwrap_or("").to_string();
            [version, status, reason]
        }
    };
    StartLine { fields, span }
}

fn fold_onto_previous(
    headers: &mut [Header],
    line: &Line,
    cbytes: &[u8],
    findings: &mut Vec<Finding>,
) {
    findings.push(Finding::new(
        "PW019",
        "header value continued via obsolete line folding".to_string(),
        Some(line.content),
    ));
    if let Some(prev) = headers.last_mut() {
        let cont = lossy(trim_ows(cbytes));
        if !prev.value.is_empty() {
            prev.value.push(' ');
        }
        prev.value.push_str(&cont);
        prev.value_span = Span::new(prev.value_span.start, line.content.end);
        prev.line_span = Span::new(prev.line_span.start, line.content.end);
    }
}

fn parse_header_line(
    line: &Line,
    cbytes: &[u8],
    headers: &mut Vec<Header>,
    findings: &mut Vec<Finding>,
) {
    let base = line.content.start;
    let Some(colon) = cbytes.iter().position(|&b| b == b':') else {
        findings.push(Finding::new(
            "PW013",
            "header line has no colon".to_string(),
            Some(line.content),
        ));
        return;
    };
    let name_bytes = &cbytes[..colon];
    let value_bytes = &cbytes[colon + 1..];
    let name_span = Span::new(base, base + colon);
    let value_span = Span::new(base + colon + 1, line.content.end);

    let trimmed_name = trim_ows(name_bytes);
    if trimmed_name.len() != name_bytes.len() {
        findings.push(Finding::new(
            "PW007",
            "whitespace sits between the field name and the colon".to_string(),
            Some(name_span),
        ));
    }
    let name = lossy(trimmed_name);
    if name.is_empty() {
        findings.push(Finding::new(
            "PW013",
            "empty header field name".to_string(),
            Some(name_span),
        ));
    } else if !trimmed_name.iter().all(|&b| is_token_byte(b)) {
        findings.push(Finding::new(
            "PW013",
            format!("field name `{name}` contains non-token bytes"),
            Some(name_span),
        ));
    }

    let value = lossy(trim_ows(value_bytes));
    headers.push(Header {
        name,
        value,
        line_span: line.content,
        name_span,
        value_span,
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    fn parse_req(raw: &[u8]) -> (Message, Vec<Finding>) {
        parse(raw, ParseMode::Request)
    }

    fn codes(findings: &[Finding]) -> Vec<&str> {
        findings.iter().map(|f| f.code).collect()
    }

    #[test]
    fn read_line_splits_crlf() {
        let buf = b"abc\r\ndef";
        let l = read_line(buf, 0);
        assert_eq!(l.term, Term::Crlf);
        assert_eq!(l.content.slice(buf), b"abc");
        assert_eq!(l.full.end, 5);
    }

    #[test]
    fn read_line_splits_bare_lf() {
        let buf = b"abc\ndef";
        let l = read_line(buf, 0);
        assert_eq!(l.term, Term::Lf);
        assert_eq!(l.content.slice(buf), b"abc");
        assert_eq!(l.full.end, 4);
    }

    #[test]
    fn parses_a_clean_request() {
        let (m, f) = parse_req(b"GET /index HTTP/1.1\r\nHost: example.test\r\n\r\n");
        assert_eq!(m.kind, MessageKind::Request);
        assert_eq!(m.start_line.method(), "GET");
        assert_eq!(m.start_line.target(), "/index");
        assert_eq!(m.start_line.version(), "HTTP/1.1");
        assert_eq!(m.headers.len(), 1);
        assert_eq!(m.headers[0].name, "Host");
        assert_eq!(m.headers[0].value, "example.test");
        assert!(f.is_empty(), "clean request had findings: {:?}", codes(&f));
    }

    #[test]
    fn auto_mode_detects_response() {
        let (m, _) = parse(b"HTTP/1.1 200 OK\r\n\r\n", ParseMode::Auto);
        assert_eq!(m.kind, MessageKind::Response);
        assert_eq!(m.start_line.resp_version(), "HTTP/1.1");
        assert_eq!(m.start_line.status(), "200");
        assert_eq!(m.start_line.reason(), "OK");
    }

    #[test]
    fn response_reason_keeps_internal_spaces() {
        let (m, _) = parse(b"HTTP/1.1 404 Not Found\r\n\r\n", ParseMode::Response);
        assert_eq!(m.start_line.reason(), "Not Found");
    }

    #[test]
    fn value_ows_is_trimmed() {
        let (m, _) = parse_req(b"GET / HTTP/1.1\r\nX-Test:   spaced   \r\n\r\n");
        assert_eq!(m.headers[0].value, "spaced");
    }

    #[test]
    fn bare_lf_flags_pw008_once_with_count() {
        let (_m, f) = parse_req(b"GET / HTTP/1.1\nHost: h\n\n");
        let lf: Vec<_> = f.iter().filter(|x| x.code == "PW008").collect();
        assert_eq!(lf.len(), 1, "PW008 should be reported once");
        assert!(lf[0].detail.contains("3"), "counts all three LF lines");
    }

    #[test]
    fn bare_cr_flags_pw009() {
        // A CR in the middle of a value, not before the LF terminator.
        let (_m, f) = parse_req(b"GET / HTTP/1.1\r\nX: a\rb\r\n\r\n");
        assert!(codes(&f).contains(&"PW009"));
    }

    #[test]
    fn non_token_name_flags_pw013() {
        let (_m, f) = parse_req(b"GET / HTTP/1.1\r\nBad Name: v\r\n\r\n");
        assert!(codes(&f).contains(&"PW013"));
    }

    #[test]
    fn obs_fold_flags_pw019_and_joins_value() {
        let (m, f) = parse_req(b"GET / HTTP/1.1\r\nX-Long: a\r\n\tb\r\n\r\n");
        assert!(codes(&f).contains(&"PW019"));
        assert_eq!(m.headers.len(), 1);
        assert_eq!(m.headers[0].value, "a b");
    }

    #[test]
    fn irregular_request_line_flags_pw014() {
        let (_m, f) = parse_req(b"GET  /double  HTTP/1.1\r\n\r\n");
        assert!(codes(&f).contains(&"PW014"));
    }

    #[test]
    fn truncated_headers_have_no_body() {
        let (m, _) = parse_req(b"GET / HTTP/1.1\r\nHost: h");
        assert_eq!(m.body_start, m.raw_len);
        assert_eq!(m.headers.len(), 1);
    }

    #[test]
    fn multiple_headers_preserve_order_and_spans() {
        let raw = b"GET / HTTP/1.1\r\nA: 1\r\nB: 2\r\n\r\n";
        let (m, _) = parse_req(raw);
        assert_eq!(m.headers[0].name, "A");
        assert_eq!(m.headers[1].name, "B");
        // Spans point back at the exact header bytes.
        assert_eq!(m.headers[0].line_span.slice(raw), b"A: 1");
        assert_eq!(m.headers[1].name_span.slice(raw), b"B");
    }
}
