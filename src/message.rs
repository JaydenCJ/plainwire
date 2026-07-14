//! The parsed message model.
//!
//! [`Message`] is the structural result of parsing a raw HTTP/1.1 byte buffer:
//! a start-line, an ordered list of [`Header`]s, and a framed [`Body`]. Every
//! part keeps the [`Span`] it came from so nothing is lost between the raw
//! bytes and the annotated view. Parsing lives in [`crate::parser`]; framing in
//! [`crate::framing`]. The end-to-end entry point is [`crate::analyze`].

use crate::findings::Finding;
use crate::span::Span;

/// Whether the message is a request or a response.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum MessageKind {
    Request,
    Response,
}

impl MessageKind {
    pub fn label(self) -> &'static str {
        match self {
            MessageKind::Request => "request",
            MessageKind::Response => "response",
        }
    }
}

/// How the caller wants the start-line interpreted.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ParseMode {
    /// Force request parsing.
    Request,
    /// Force response parsing.
    Response,
    /// Guess: a first token of `HTTP/x` means a response, else a request.
    Auto,
}

/// The first line of the message, split into its three fields.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StartLine {
    /// method + target + version (request) or version + status + reason (response).
    pub fields: [String; 3],
    pub span: Span,
}

impl StartLine {
    /// Field accessors named for the request form.
    pub fn method(&self) -> &str {
        &self.fields[0]
    }
    pub fn target(&self) -> &str {
        &self.fields[1]
    }
    pub fn version(&self) -> &str {
        &self.fields[2]
    }
    /// Field accessors named for the response form
    /// (`HTTP-version SP status-code SP reason-phrase`).
    pub fn resp_version(&self) -> &str {
        &self.fields[0]
    }
    pub fn status(&self) -> &str {
        &self.fields[1]
    }
    pub fn reason(&self) -> &str {
        &self.fields[2]
    }
}

/// One header field.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Header {
    /// The field name with surrounding whitespace removed.
    pub name: String,
    /// The field value with leading/trailing optional whitespace removed.
    pub value: String,
    /// Span of the whole header line (excluding the line terminator).
    pub line_span: Span,
    /// Span of the field-name bytes.
    pub name_span: Span,
    /// Span of the field-value bytes (after the colon, OWS included).
    pub value_span: Span,
}

impl Header {
    /// Case-insensitive name comparison, per RFC field-name semantics.
    pub fn is(&self, name: &str) -> bool {
        self.name.eq_ignore_ascii_case(name)
    }
}

/// The framing decision plainwire reached for the body.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Framing {
    /// No body (a request with neither Content-Length nor Transfer-Encoding).
    Empty,
    /// Fixed length from Content-Length.
    ContentLength,
    /// Chunked transfer coding.
    Chunked,
    /// Response body that runs until the connection closes.
    UntilClose,
    /// The framing headers contradict each other; length is undeterminable.
    Ambiguous,
}

impl Framing {
    pub fn label(self) -> &'static str {
        match self {
            Framing::Empty => "empty",
            Framing::ContentLength => "content-length",
            Framing::Chunked => "chunked",
            Framing::UntilClose => "until-close",
            Framing::Ambiguous => "ambiguous",
        }
    }
}

/// One decoded chunk of a chunked body.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Chunk {
    /// Declared size in bytes.
    pub size: usize,
    /// Span of the chunk-size line (size + optional extension).
    pub size_span: Span,
    /// Span of the chunk data bytes.
    pub data_span: Span,
    /// Raw chunk extension text (everything after `;` on the size line), if any.
    pub extension: Option<String>,
}

/// The body region and how it was framed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Body {
    pub framing: Framing,
    /// Span of the body bytes actually present in the buffer.
    pub span: Span,
    /// For Content-Length framing, the declared length.
    pub declared_len: Option<usize>,
    /// Decoded length: Content-Length bytes present, or sum of chunk sizes.
    pub decoded_len: usize,
    /// Parsed chunks (chunked framing only).
    pub chunks: Vec<Chunk>,
    /// Whether the body is fully present (chunked terminator seen / CL satisfied).
    pub complete: bool,
}

impl Body {
    pub fn empty(at: usize) -> Self {
        Body {
            framing: Framing::Empty,
            span: Span::empty(at),
            declared_len: None,
            decoded_len: 0,
            chunks: Vec::new(),
            complete: true,
        }
    }
}

/// A fully parsed and analyzed message.
#[derive(Debug, Clone)]
pub struct Message {
    pub kind: MessageKind,
    pub start_line: StartLine,
    pub headers: Vec<Header>,
    pub body: Body,
    /// Byte offset where the body begins (after the blank line).
    pub body_start: usize,
    /// Total length of the raw input.
    pub raw_len: usize,
}

/// The result of [`crate::analyze`]: the message plus every finding, in the
/// order they were produced (structural first, then framing).
#[derive(Debug, Clone)]
pub struct Analysis {
    pub message: Message,
    pub findings: Vec<Finding>,
}

/// Render a byte slice as a single printable line: printable ASCII is kept,
/// control bytes become the C-style escapes `\r \n \t \0`, everything else
/// becomes `\xHH`. Used by the annotator and JSON so a raw value is never
/// dumped verbatim into the terminal.
pub fn escape_bytes(bytes: &[u8]) -> String {
    let mut out = String::with_capacity(bytes.len());
    for &b in bytes {
        match b {
            b'\r' => out.push_str("\\r"),
            b'\n' => out.push_str("\\n"),
            b'\t' => out.push_str("\\t"),
            0 => out.push_str("\\0"),
            0x20..=0x7e => out.push(b as char),
            _ => out.push_str(&format!("\\x{b:02x}")),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn start_line_accessors_alias_the_same_fields() {
        let sl = StartLine {
            fields: ["POST".to_string(), "/x".to_string(), "HTTP/1.1".to_string()],
            span: Span::new(0, 15),
        };
        assert_eq!(sl.method(), "POST");
        assert_eq!(sl.target(), "/x");
        assert_eq!(sl.version(), "HTTP/1.1");
        // Response-flavoured accessors read the same slots.
        assert_eq!(sl.status(), "/x");
    }

    #[test]
    fn header_case_insensitive_match() {
        let h = Header {
            name: "Content-Length".to_string(),
            value: "5".to_string(),
            line_span: Span::new(0, 18),
            name_span: Span::new(0, 14),
            value_span: Span::new(15, 16),
        };
        assert!(h.is("content-length"));
        assert!(h.is("CONTENT-LENGTH"));
        assert!(!h.is("content-type"));
    }

    #[test]
    fn escape_bytes_makes_controls_visible() {
        assert_eq!(escape_bytes(b"a\r\nb"), "a\\r\\nb");
        assert_eq!(escape_bytes(b"\t"), "\\t");
        assert_eq!(escape_bytes(&[0x00, 0x80, b'z']), "\\0\\x80z");
        assert_eq!(escape_bytes(b"plain text 123"), "plain text 123");
    }

    #[test]
    fn empty_body_is_complete_and_zero_length() {
        let b = Body::empty(42);
        assert_eq!(b.framing, Framing::Empty);
        assert!(b.complete);
        assert_eq!(b.decoded_len, 0);
        assert_eq!(b.span, Span::empty(42));
    }
}
