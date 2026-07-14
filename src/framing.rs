//! Body-framing analysis: the part that decides how long the body is and, in
//! doing so, surfaces the request-smuggling ambiguities.
//!
//! HTTP/1.1 message length follows a strict precedence (RFC 9112 §6.1–6.3):
//! Transfer-Encoding with a final `chunked` coding wins; otherwise a single
//! valid Content-Length applies; a message carrying both, or contradictory
//! copies of either, is unrecoverable. plainwire reproduces that precedence,
//! frames the body accordingly, and reports every point where two conforming
//! parsers could reach different lengths — which is exactly a desync.

use crate::chunked;
use crate::findings::Finding;
use crate::message::{Body, Framing, Header, Message, MessageKind};
use crate::span::Span;

/// Collected view of one framing-relevant header.
struct HeaderRef {
    value: String,
    span: Span,
}

fn collect(headers: &[Header], name: &str) -> Vec<HeaderRef> {
    headers
        .iter()
        .filter(|h| h.is(name))
        .map(|h| HeaderRef {
            value: h.value.clone(),
            span: h.line_span,
        })
        .collect()
}

fn combine_spans(a: Span, b: Span) -> Span {
    Span::new(a.start.min(b.start), a.end.max(b.end))
}

/// Parse a Content-Length token as a non-negative decimal.
fn parse_cl(token: &str) -> Option<u64> {
    if token.is_empty() || !token.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    token.parse::<u64>().ok()
}

/// Whether a transfer-coding token is an obfuscated attempt at `chunked`
/// (contains the substring but is not exactly `chunked` after case folding).
fn is_obfuscated_chunked(token: &str) -> bool {
    let lower = token.to_ascii_lowercase();
    lower.contains("chunked") && lower != "chunked"
}

/// Resolve Content-Length across all its header fields.
struct ClResolution {
    /// The single agreed length, if exactly one valid value was found.
    value: Option<u64>,
    /// True if a Content-Length field is present at all.
    present: bool,
    /// True if any value was unparseable — length is then indeterminate.
    invalid: bool,
}

fn resolve_content_length(cls: &[HeaderRef], findings: &mut Vec<Finding>) -> ClResolution {
    if cls.is_empty() {
        return ClResolution {
            value: None,
            present: false,
            invalid: false,
        };
    }
    if cls.len() > 1 {
        findings.push(Finding::new(
            "PW002",
            format!("{} Content-Length header fields are present", cls.len()),
            Some(combine_spans(cls[0].span, cls[cls.len() - 1].span)),
        ));
    }
    let mut values: Vec<u64> = Vec::new();
    let mut invalid = false;
    for cl in cls {
        for token in cl.value.split(',') {
            let token = token.trim();
            match parse_cl(token) {
                Some(v) => {
                    if !values.contains(&v) {
                        values.push(v);
                    }
                }
                None => {
                    invalid = true;
                    findings.push(Finding::new(
                        "PW010",
                        format!("Content-Length value `{token}` is not a bare decimal integer"),
                        Some(cl.span),
                    ));
                }
            }
        }
    }
    if values.len() > 1 {
        let list = values
            .iter()
            .map(|v| v.to_string())
            .collect::<Vec<_>>()
            .join(", ");
        findings.push(Finding::new(
            "PW003",
            format!("Content-Length resolves to multiple values: {list}"),
            Some(combine_spans(cls[0].span, cls[cls.len() - 1].span)),
        ));
    }
    ClResolution {
        value: if !invalid && values.len() == 1 {
            Some(values[0])
        } else {
            None
        },
        present: true,
        invalid,
    }
}

/// Resolve Transfer-Encoding across all its header fields.
struct TeResolution {
    present: bool,
    final_is_chunked: bool,
    span: Option<Span>,
}

fn resolve_transfer_encoding(tes: &[HeaderRef], findings: &mut Vec<Finding>) -> TeResolution {
    if tes.is_empty() {
        return TeResolution {
            present: false,
            final_is_chunked: false,
            span: None,
        };
    }
    let span = combine_spans(tes[0].span, tes[tes.len() - 1].span);
    if tes.len() > 1 {
        findings.push(Finding::new(
            "PW004",
            format!("{} Transfer-Encoding header fields are present", tes.len()),
            Some(span),
        ));
    }
    // Flatten every coding token in order.
    let mut codings: Vec<String> = Vec::new();
    for te in tes {
        for token in te.value.split(',') {
            let token = token.trim();
            if token.is_empty() {
                continue;
            }
            if is_obfuscated_chunked(token) {
                findings.push(Finding::new(
                    "PW006",
                    format!(
                        "transfer coding `{token}` mimics chunked; strict and lenient parsers will disagree"
                    ),
                    Some(te.span),
                ));
            }
            codings.push(token.to_ascii_lowercase());
        }
    }
    let final_is_chunked = codings.last().map(|c| c == "chunked").unwrap_or(false);
    if !final_is_chunked {
        let detail = if codings.iter().any(|c| c == "chunked") {
            "chunked is present but is not the final transfer coding".to_string()
        } else {
            format!(
                "final transfer coding is `{}`, not chunked; request body length is undeterminable",
                codings.last().cloned().unwrap_or_default()
            )
        };
        findings.push(Finding::new("PW005", detail, Some(span)));
    }
    TeResolution {
        present: true,
        final_is_chunked,
        span: Some(span),
    }
}

/// Run the full framing analysis, filling `msg.body` and appending findings.
pub fn analyze(msg: &mut Message, findings: &mut Vec<Finding>, buf: &[u8]) {
    let cls = collect(&msg.headers, "content-length");
    let tes = collect(&msg.headers, "transfer-encoding");
    let hosts = collect(&msg.headers, "host");

    if msg.kind == MessageKind::Request {
        if hosts.is_empty() {
            findings.push(Finding::new(
                "PW015",
                "HTTP/1.1 request has no Host header".to_string(),
                Some(msg.start_line.span),
            ));
        } else if hosts.len() > 1 {
            findings.push(Finding::new(
                "PW016",
                format!("{} Host header fields are present", hosts.len()),
                Some(combine_spans(hosts[0].span, hosts[hosts.len() - 1].span)),
            ));
        }
    }

    let cl = resolve_content_length(&cls, findings);
    let te = resolve_transfer_encoding(&tes, findings);

    if cl.present && te.present {
        let span = combine_spans(cls[0].span, te.span.unwrap_or(tes[tes.len() - 1].span));
        findings.push(Finding::new(
            "PW001",
            "both Content-Length and Transfer-Encoding are present; conforming servers use \
             chunked and ignore Content-Length"
                .to_string(),
            Some(span),
        ));
    }

    let start = msg.body_start;
    let len = buf.len();
    let body = if te.present && te.final_is_chunked {
        // Transfer-Encoding wins even when Content-Length is also present.
        let scan = chunked::scan_chunks(buf, start, findings);
        if scan.end < len {
            findings.push(Finding::new(
                "PW017",
                format!(
                    "{} byte(s) follow the chunked body (possible smuggled request prefix)",
                    len - scan.end
                ),
                Some(Span::new(scan.end, len)),
            ));
        }
        Body {
            framing: Framing::Chunked,
            span: Span::new(start, scan.end.min(len)),
            declared_len: None,
            decoded_len: scan.decoded_len,
            chunks: scan.chunks,
            complete: scan.complete,
        }
    } else if te.present {
        // TE present but not chunked-final: length cannot be determined.
        Body {
            framing: Framing::Ambiguous,
            span: Span::new(start, len),
            declared_len: None,
            decoded_len: len - start,
            chunks: Vec::new(),
            complete: false,
        }
    } else if let Some(n) = cl.value {
        let n = n as usize;
        let present = len - start;
        let body_end = start.saturating_add(n).min(len);
        if present < n {
            findings.push(Finding::new(
                "PW018",
                format!("Content-Length is {n} but only {present} body byte(s) are present"),
                Some(Span::new(start, len)),
            ));
        } else if present > n {
            findings.push(Finding::new(
                "PW017",
                format!(
                    "{} byte(s) follow the Content-Length body (possible smuggled request prefix)",
                    present - n
                ),
                Some(Span::new(body_end, len)),
            ));
        }
        Body {
            framing: Framing::ContentLength,
            span: Span::new(start, body_end),
            declared_len: Some(n),
            decoded_len: present.min(n),
            chunks: Vec::new(),
            complete: present >= n,
        }
    } else if cl.invalid {
        // Content-Length present but unparseable: indeterminate.
        Body {
            framing: Framing::Ambiguous,
            span: Span::new(start, len),
            declared_len: None,
            decoded_len: len - start,
            chunks: Vec::new(),
            complete: false,
        }
    } else if msg.kind == MessageKind::Response {
        // No framing headers on a response: body runs until connection close.
        Body {
            framing: Framing::UntilClose,
            span: Span::new(start, len),
            declared_len: None,
            decoded_len: len - start,
            chunks: Vec::new(),
            complete: true,
        }
    } else {
        // A request with no framing headers has no body.
        if len > start {
            findings.push(Finding::new(
                "PW017",
                format!(
                    "{} byte(s) follow a body-less request (possible smuggled/pipelined request)",
                    len - start
                ),
                Some(Span::new(start, len)),
            ));
        }
        Body::empty(start)
    };

    msg.body = body;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::message::ParseMode;
    use crate::parser;

    fn analyze_bytes(raw: &[u8], mode: ParseMode) -> (Message, Vec<Finding>) {
        let (mut msg, mut findings) = parser::parse(raw, mode);
        analyze(&mut msg, &mut findings, raw);
        (msg, findings)
    }

    fn req(raw: &[u8]) -> (Message, Vec<Finding>) {
        analyze_bytes(raw, ParseMode::Request)
    }

    fn codes(f: &[Finding]) -> Vec<&str> {
        f.iter().map(|x| x.code).collect()
    }

    #[test]
    fn bodyless_request_is_empty_framing() {
        let (m, f) = req(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert_eq!(m.body.framing, Framing::Empty);
        assert_eq!(m.body.decoded_len, 0);
        assert!(f.is_empty(), "unexpected: {:?}", codes(&f));
    }

    #[test]
    fn content_length_frames_the_body() {
        let (m, f) = req(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello");
        assert_eq!(m.body.framing, Framing::ContentLength);
        assert_eq!(m.body.declared_len, Some(5));
        assert_eq!(m.body.decoded_len, 5);
        assert!(m.body.complete);
        assert!(f.is_empty());
    }

    #[test]
    fn short_body_flags_incomplete() {
        let (m, f) = req(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 10\r\n\r\nhi");
        assert!(!m.body.complete);
        assert!(codes(&f).contains(&"PW018"));
    }

    #[test]
    fn both_cl_and_te_flag_pw001() {
        let raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n";
        let (m, f) = req(raw);
        assert!(codes(&f).contains(&"PW001"));
        // Chunked wins the framing decision.
        assert_eq!(m.body.framing, Framing::Chunked);
    }

    #[test]
    fn duplicate_content_length_flags_pw002() {
        let (_m, f) = req(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 5\r\n\r\nhello",
        );
        assert!(codes(&f).contains(&"PW002"));
        // Same value twice is not a conflict.
        assert!(!codes(&f).contains(&"PW003"));
    }

    #[test]
    fn conflicting_content_length_flags_pw003() {
        let (_m, f) = req(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\nContent-Length: 6\r\n\r\nhello",
        );
        assert!(codes(&f).contains(&"PW002"));
        assert!(codes(&f).contains(&"PW003"));
    }

    #[test]
    fn invalid_content_length_flags_pw010() {
        let (m, f) = req(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 0x5\r\n\r\nhello");
        assert!(codes(&f).contains(&"PW010"));
        assert_eq!(m.body.framing, Framing::Ambiguous);
    }

    #[test]
    fn chunked_request_frames_via_te() {
        let (m, f) = req(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
        assert_eq!(m.body.framing, Framing::Chunked);
        assert_eq!(m.body.decoded_len, 5);
        assert!(m.body.complete);
        assert!(f.is_empty());
    }

    #[test]
    fn te_not_chunked_final_flags_pw005() {
        let (m, f) = req(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: gzip\r\n\r\nbody");
        assert!(codes(&f).contains(&"PW005"));
        assert_eq!(m.body.framing, Framing::Ambiguous);
    }

    #[test]
    fn casing_chunked_is_not_obfuscation() {
        // Transfer-coding names are case-insensitive; Chunked is legitimate.
        let (m, f) =
            req(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: Chunked\r\n\r\n0\r\n\r\n");
        assert_eq!(m.body.framing, Framing::Chunked);
        assert!(!codes(&f).contains(&"PW006"));
        assert!(!codes(&f).contains(&"PW005"));
    }

    #[test]
    fn missing_host_flags_pw015() {
        let (_m, f) = req(b"GET / HTTP/1.1\r\n\r\n");
        assert!(codes(&f).contains(&"PW015"));
    }

    #[test]
    fn multiple_host_flags_pw016() {
        let (_m, f) = req(b"GET / HTTP/1.1\r\nHost: a\r\nHost: b\r\n\r\n");
        assert!(codes(&f).contains(&"PW016"));
    }

    #[test]
    fn response_without_framing_reads_until_close() {
        let (m, _f) = analyze_bytes(
            b"HTTP/1.1 200 OK\r\nServer: x\r\n\r\nbody bytes",
            ParseMode::Response,
        );
        assert_eq!(m.body.framing, Framing::UntilClose);
        assert_eq!(m.body.decoded_len, 10);
    }

    #[test]
    fn bodyless_request_with_trailing_bytes_flags_pw017() {
        let (_m, f) = req(b"GET / HTTP/1.1\r\nHost: h\r\n\r\nGET /smuggled HTTP/1.1\r\n");
        assert!(codes(&f).contains(&"PW017"));
    }
}
