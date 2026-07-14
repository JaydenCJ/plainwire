//! The finding catalog: every framing anomaly plainwire can report.
//!
//! A [`Finding`] is one observation about a message — a smuggling-relevant
//! ambiguity, a spec violation, or an informational note — carrying a stable
//! `PWnnn` code, a severity, a human title, a specific detail string and the
//! byte [`Span`] it refers to. Codes are stable across releases so they can be
//! grepped for in CI (`plainwire lint`) or referenced in advisories.

use crate::span::Span;

/// How seriously a finding should be taken.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Severity {
    /// A concrete desync vector or a framing rule violation. `lint` fails.
    Error,
    /// Suspicious or non-conforming, but not on its own a desync.
    Warn,
    /// Informational: worth surfacing, harmless by itself.
    Info,
}

impl Severity {
    /// Lowercase label used in text output and JSON.
    pub fn label(self) -> &'static str {
        match self {
            Severity::Error => "error",
            Severity::Warn => "warn",
            Severity::Info => "info",
        }
    }

    /// Higher rank = more severe. Used to sort and to implement `--fail-on`.
    pub fn rank(self) -> u8 {
        match self {
            Severity::Error => 3,
            Severity::Warn => 2,
            Severity::Info => 1,
        }
    }
}

/// A static catalog entry describing one finding code.
#[derive(Debug, Clone, Copy)]
pub struct FindingSpec {
    pub code: &'static str,
    pub slug: &'static str,
    pub severity: Severity,
    /// One-line title.
    pub title: &'static str,
    /// A sentence explaining why the finding matters (shown by `plainwire codes`).
    pub description: &'static str,
}

/// The complete catalog. Order is the presentation order for `plainwire codes`.
pub const CATALOG: &[FindingSpec] = &[
    FindingSpec {
        code: "PW001",
        slug: "both-cl-te",
        severity: Severity::Error,
        title: "Content-Length and Transfer-Encoding are both present",
        description: "A message carries both framing headers. RFC 9112 says the recipient MUST \
                      use Transfer-Encoding and treat the message as unrecoverable if it forwards \
                      it without removing Content-Length. When a front-end and back-end disagree \
                      about which header wins, the leftover bytes become a smuggled request \
                      (the classic CL.TE / TE.CL desync).",
    },
    FindingSpec {
        code: "PW002",
        slug: "duplicate-content-length",
        severity: Severity::Error,
        title: "Multiple Content-Length header fields",
        description: "More than one Content-Length field was sent. Servers differ on whether they \
                      take the first, the last, or reject the message, so two hops can frame the \
                      body differently.",
    },
    FindingSpec {
        code: "PW003",
        slug: "conflicting-content-length",
        severity: Severity::Error,
        title: "Content-Length values disagree",
        description: "Content-Length resolves to more than one distinct value (across duplicate \
                      fields or a comma list). The body length is ambiguous and MUST be rejected.",
    },
    FindingSpec {
        code: "PW004",
        slug: "duplicate-transfer-encoding",
        severity: Severity::Error,
        title: "Multiple Transfer-Encoding header fields",
        description: "Transfer-Encoding appears more than once. If only one of them names chunked, \
                      a lenient server may honour it while a strict one does not — the TE.TE vector.",
    },
    FindingSpec {
        code: "PW005",
        slug: "te-not-chunked-final",
        severity: Severity::Error,
        title: "Transfer-Encoding does not end in chunked",
        description: "The final transfer coding is not chunked (or chunked is missing). For a \
                      request the body length is then undeterminable and the server ought to \
                      answer 400; leniency here is a desync surface.",
    },
    FindingSpec {
        code: "PW006",
        slug: "obfuscated-transfer-encoding",
        severity: Severity::Error,
        title: "Transfer-Encoding coding is obfuscated",
        description: "A transfer coding is written so that only some parsers recognize it as \
                      chunked (for example xchunked, a tab before the value, or odd casing). \
                      This is a deliberate technique to make two servers frame the body differently.",
    },
    FindingSpec {
        code: "PW007",
        slug: "whitespace-before-colon",
        severity: Severity::Error,
        title: "Whitespace between header name and colon",
        description: "A space or tab sits between the field name and the colon. RFC 9112 forbids it; \
                      some servers strip the space and honour the header, others treat the whole \
                      line as invalid. On a framing header this splits parsers apart.",
    },
    FindingSpec {
        code: "PW008",
        slug: "bare-lf-line-ending",
        severity: Severity::Warn,
        title: "Line terminated by a bare LF",
        description: "A line ends with LF instead of CRLF. RFC 9112 lets a recipient treat a bare \
                      LF as a line terminator, so a header a strict CRLF parser ignores can still \
                      take effect downstream — a well-known desync trick.",
    },
    FindingSpec {
        code: "PW009",
        slug: "bare-cr",
        severity: Severity::Warn,
        title: "Bare CR inside a line",
        description: "A carriage return appears that is not part of a CRLF terminator. Parsers \
                      disagree on whether it ends the line, is stripped, or is kept in the value.",
    },
    FindingSpec {
        code: "PW010",
        slug: "invalid-content-length",
        severity: Severity::Error,
        title: "Content-Length is not a valid integer",
        description: "The value is not a bare non-negative decimal (it has a sign, spaces, hex, or \
                      trailing junk). Lenient parsers may still extract a number, framing the body \
                      differently from strict ones.",
    },
    FindingSpec {
        code: "PW011",
        slug: "invalid-chunk-size",
        severity: Severity::Error,
        title: "Chunk size is not valid hexadecimal",
        description: "A chunk-size line is not a clean hex number, or the declared size does not \
                      line up with the following CRLF. The chunked stream cannot be trusted.",
    },
    FindingSpec {
        code: "PW012",
        slug: "chunk-extension",
        severity: Severity::Info,
        title: "Chunk extension present",
        description: "A chunk carries a ;name=value extension. Harmless on its own, but a surface \
                      for smuggling padding and for parser disagreement.",
    },
    FindingSpec {
        code: "PW013",
        slug: "non-token-header-name",
        severity: Severity::Warn,
        title: "Header name contains non-token bytes",
        description: "The field name uses bytes outside the RFC token set (or the line has no \
                      colon). Such lines are handled inconsistently across servers.",
    },
    FindingSpec {
        code: "PW014",
        slug: "request-target-whitespace",
        severity: Severity::Warn,
        title: "Extra whitespace in the request line",
        description: "The request line is not exactly method SP target SP version. Extra or tab \
                      whitespace can shift how the target and version are parsed.",
    },
    FindingSpec {
        code: "PW015",
        slug: "missing-host",
        severity: Severity::Warn,
        title: "HTTP/1.1 request without a Host header",
        description: "HTTP/1.1 requires exactly one Host header. Its absence is malformed and \
                      routing becomes implementation-defined.",
    },
    FindingSpec {
        code: "PW016",
        slug: "multiple-host",
        severity: Severity::Error,
        title: "Multiple Host header fields",
        description: "More than one Host was sent. Different hops may route on different Host \
                      values, which is a request-routing and cache-poisoning vector.",
    },
    FindingSpec {
        code: "PW017",
        slug: "trailing-body-bytes",
        severity: Severity::Warn,
        title: "Bytes remain after the framed body",
        description: "The message is fully framed but bytes follow it. On a request boundary those \
                      bytes are the prefix of a smuggled request; confirm they are intended \
                      pipelining.",
    },
    FindingSpec {
        code: "PW018",
        slug: "incomplete-body",
        severity: Severity::Warn,
        title: "Body is shorter than its declared length",
        description: "Fewer body bytes are present than Content-Length (or the chunked stream) \
                      promised. The message is truncated or waiting for more data.",
    },
    FindingSpec {
        code: "PW019",
        slug: "obsolete-line-folding",
        severity: Severity::Warn,
        title: "Obsolete header line folding (obs-fold)",
        description: "A header value is continued on a folded line beginning with whitespace. \
                      RFC 9112 deprecates obs-fold; senders and receivers disagree on how to \
                      unfold it.",
    },
    FindingSpec {
        code: "PW020",
        slug: "missing-final-chunk",
        severity: Severity::Error,
        title: "Chunked body is missing its terminating 0-size chunk",
        description: "A chunked message never reached the 0 CRLF CRLF terminator. The receiver \
                      keeps reading, so trailing bytes can be absorbed into this message or leak \
                      into the next.",
    },
];

/// Look up a catalog entry by code. Panics on an unknown code, which can only
/// happen from a programming error inside plainwire (covered by a test).
pub fn spec(code: &str) -> &'static FindingSpec {
    CATALOG
        .iter()
        .find(|s| s.code == code)
        .unwrap_or_else(|| panic!("unknown finding code {code:?}"))
}

/// One observation about a parsed message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub code: &'static str,
    pub slug: &'static str,
    pub severity: Severity,
    pub title: &'static str,
    /// A specific, message-dependent explanation (values, counts, offsets).
    pub detail: String,
    /// The bytes this finding is about, if it maps to a region.
    pub span: Option<Span>,
}

impl Finding {
    /// Build a finding for `code`, filling severity/slug/title from the catalog.
    pub fn new(code: &'static str, detail: impl Into<String>, span: Option<Span>) -> Self {
        let s = spec(code);
        Finding {
            code: s.code,
            slug: s.slug,
            severity: s.severity,
            title: s.title,
            detail: detail.into(),
            span,
        }
    }
}

/// Count of findings by severity, for summaries and exit codes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Counts {
    pub error: usize,
    pub warn: usize,
    pub info: usize,
}

impl Counts {
    pub fn of(findings: &[Finding]) -> Self {
        let mut c = Counts::default();
        for f in findings {
            match f.severity {
                Severity::Error => c.error += 1,
                Severity::Warn => c.warn += 1,
                Severity::Info => c.info += 1,
            }
        }
        c
    }

    /// Total findings.
    pub fn total(&self) -> usize {
        self.error + self.warn + self.info
    }

    /// Whether any finding is at least as severe as `threshold`.
    pub fn any_at_least(&self, threshold: Severity) -> bool {
        (self.error > 0 && Severity::Error.rank() >= threshold.rank())
            || (self.warn > 0 && Severity::Warn.rank() >= threshold.rank())
            || (self.info > 0 && Severity::Info.rank() >= threshold.rank())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_code_is_unique_and_well_formed() {
        // Codes must be unique, in PWnnn form, with a slug and non-empty text.
        let mut seen = std::collections::BTreeSet::new();
        for s in CATALOG {
            assert!(seen.insert(s.code), "duplicate code {}", s.code);
            assert!(s.code.starts_with("PW"), "bad code {}", s.code);
            assert_eq!(s.code.len(), 5, "code {} not PWnnn", s.code);
            assert!(s.code[2..].chars().all(|c| c.is_ascii_digit()));
            assert!(!s.slug.is_empty());
            assert!(!s.title.is_empty());
            assert!(s.description.len() > 20, "thin description for {}", s.code);
        }
    }

    #[test]
    fn slugs_are_unique() {
        let mut seen = std::collections::BTreeSet::new();
        for s in CATALOG {
            assert!(seen.insert(s.slug), "duplicate slug {}", s.slug);
        }
    }

    #[test]
    fn new_fills_metadata_from_catalog() {
        let f = Finding::new("PW001", "detail here", Some(Span::new(0, 10)));
        assert_eq!(f.slug, "both-cl-te");
        assert_eq!(f.severity, Severity::Error);
        assert_eq!(
            f.title,
            "Content-Length and Transfer-Encoding are both present"
        );
        assert_eq!(f.detail, "detail here");
    }

    #[test]
    #[should_panic(expected = "unknown finding code")]
    fn unknown_code_panics() {
        Finding::new("PW999", "x", None);
    }

    #[test]
    fn severity_rank_orders_error_over_warn_over_info() {
        assert!(Severity::Error.rank() > Severity::Warn.rank());
        assert!(Severity::Warn.rank() > Severity::Info.rank());
    }

    #[test]
    fn counts_and_thresholds() {
        let fs = vec![
            Finding::new("PW001", "a", None),
            Finding::new("PW008", "b", None),
            Finding::new("PW012", "c", None),
        ];
        let c = Counts::of(&fs);
        assert_eq!(c.error, 1);
        assert_eq!(c.warn, 1);
        assert_eq!(c.info, 1);
        assert_eq!(c.total(), 3);
        assert!(c.any_at_least(Severity::Error));
        assert!(c.any_at_least(Severity::Info));

        let only_info = Counts::of(&[Finding::new("PW012", "c", None)]);
        assert!(!only_info.any_at_least(Severity::Error));
        assert!(only_info.any_at_least(Severity::Info));
    }
}
