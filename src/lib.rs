//! plainwire — craft and inspect raw HTTP/1.1 exchanges byte-by-byte, flagging
//! Content-Length / Transfer-Encoding smuggling ambiguities.
//!
//! netcat shows you bytes with no meaning. plainwire parses the same bytes into
//! a start-line, headers and a framed body, keeping an exact byte [`span::Span`]
//! for every element, then annotates them and reports the framing ambiguities
//! that make HTTP request smuggling (desync) possible.
//!
//! The library is layered so each concern is independently testable:
//!
//! - [`parser`] turns raw bytes into a structural [`message::Message`] and the
//!   line-level findings (bad endings, whitespace before a colon, obs-fold).
//! - [`framing`] applies the RFC 9112 body-length precedence and reports the
//!   CL/TE ambiguities, delegating chunk parsing to [`chunked`].
//! - [`annotate`], [`hexdump`] and [`json`] render the result.
//! - [`craft`] builds raw requests, including known desync gadgets.
//!
//! [`analyze`] ties parsing and framing together into an [`message::Analysis`].

pub mod annotate;
pub mod chunked;
pub mod cli;
pub mod craft;
pub mod findings;
pub mod framing;
pub mod hexdump;
pub mod json;
pub mod message;
pub mod parser;
pub mod span;

use message::{Analysis, ParseMode};

/// Parse and framing-analyze a raw HTTP/1.1 message.
///
/// This never fails: any input produces an [`Analysis`]. Malformed input is
/// reported through findings rather than an error, because "malformed" is
/// exactly what the tool exists to describe.
pub fn analyze(bytes: &[u8], mode: ParseMode) -> Analysis {
    let (mut message, mut findings) = parser::parse(bytes, mode);
    framing::analyze(&mut message, &mut findings, bytes);
    Analysis { message, findings }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn analyze_is_total_on_empty_input() {
        let a = analyze(b"", ParseMode::Auto);
        assert_eq!(a.message.raw_len, 0);
    }

    #[test]
    fn analyze_a_clean_request_has_no_findings() {
        let a = analyze(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", ParseMode::Auto);
        assert!(a.findings.is_empty());
        assert_eq!(a.message.headers.len(), 1);
    }

    #[test]
    fn analyze_detects_a_desync() {
        let a = analyze(
            b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG",
            ParseMode::Request,
        );
        let codes: Vec<_> = a.findings.iter().map(|f| f.code).collect();
        assert!(codes.contains(&"PW001"));
    }
}
