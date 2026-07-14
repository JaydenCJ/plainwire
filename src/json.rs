//! Zero-dependency JSON output for `plainwire inspect --json` and `plainwire
//! lint --json`.
//!
//! A byte-accurate tool should not hand its framing decisions to a third-party
//! serializer, so plainwire ships its own small pretty-printer over a tagged
//! value tree. Field order is fixed for stable, diff-friendly output.

use crate::findings::Finding;
use crate::message::{Analysis, Body, Message, StartLine};
use crate::span::Span;

/// A minimal JSON value tree.
pub enum J {
    Null,
    Bool(bool),
    Num(u64),
    Str(String),
    Arr(Vec<J>),
    Obj(Vec<(&'static str, J)>),
}

impl J {
    fn span(s: Span) -> J {
        J::Arr(vec![J::Num(s.start as u64), J::Num(s.end as u64)])
    }
    fn str(s: &str) -> J {
        J::Str(s.to_string())
    }
    fn opt_num(v: Option<usize>) -> J {
        match v {
            Some(n) => J::Num(n as u64),
            None => J::Null,
        }
    }
}

fn escape(s: &str, out: &mut String) {
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            '\u{08}' => out.push_str("\\b"),
            '\u{0c}' => out.push_str("\\f"),
            c if (c as u32) < 0x20 => out.push_str(&format!("\\u{:04x}", c as u32)),
            c => out.push(c),
        }
    }
    out.push('"');
}

fn write(value: &J, indent: usize, out: &mut String) {
    let pad = "  ".repeat(indent);
    let pad1 = "  ".repeat(indent + 1);
    match value {
        J::Null => out.push_str("null"),
        J::Bool(b) => out.push_str(if *b { "true" } else { "false" }),
        J::Num(n) => out.push_str(&n.to_string()),
        J::Str(s) => escape(s, out),
        J::Arr(items) => {
            if items.is_empty() {
                out.push_str("[]");
                return;
            }
            // Spans (a two-number array) print inline for compactness.
            let all_nums = items.iter().all(|i| matches!(i, J::Num(_)));
            if all_nums {
                out.push('[');
                for (k, item) in items.iter().enumerate() {
                    if k > 0 {
                        out.push_str(", ");
                    }
                    write(item, 0, out);
                }
                out.push(']');
                return;
            }
            out.push_str("[\n");
            for (k, item) in items.iter().enumerate() {
                out.push_str(&pad1);
                write(item, indent + 1, out);
                if k + 1 < items.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push(']');
        }
        J::Obj(fields) => {
            if fields.is_empty() {
                out.push_str("{}");
                return;
            }
            out.push_str("{\n");
            for (k, (key, val)) in fields.iter().enumerate() {
                out.push_str(&pad1);
                escape(key, out);
                out.push_str(": ");
                write(val, indent + 1, out);
                if k + 1 < fields.len() {
                    out.push(',');
                }
                out.push('\n');
            }
            out.push_str(&pad);
            out.push('}');
        }
    }
}

fn start_line_json(sl: &StartLine) -> J {
    J::Obj(vec![
        ("span", J::span(sl.span)),
        (
            "fields",
            J::Arr(sl.fields.iter().map(|f| J::str(f)).collect()),
        ),
    ])
}

fn body_json(b: &Body) -> J {
    let chunks = b
        .chunks
        .iter()
        .map(|c| {
            J::Obj(vec![
                ("size", J::Num(c.size as u64)),
                ("size_span", J::span(c.size_span)),
                ("data_span", J::span(c.data_span)),
                (
                    "extension",
                    match &c.extension {
                        Some(e) => J::str(e),
                        None => J::Null,
                    },
                ),
            ])
        })
        .collect();
    J::Obj(vec![
        ("framing", J::str(b.framing.label())),
        ("span", J::span(b.span)),
        ("declared_len", J::opt_num(b.declared_len)),
        ("decoded_len", J::Num(b.decoded_len as u64)),
        ("complete", J::Bool(b.complete)),
        ("chunks", J::Arr(chunks)),
    ])
}

fn finding_json(f: &Finding) -> J {
    J::Obj(vec![
        ("code", J::str(f.code)),
        ("slug", J::str(f.slug)),
        ("severity", J::str(f.severity.label())),
        ("title", J::str(f.title)),
        ("detail", J::str(&f.detail)),
        (
            "span",
            match f.span {
                Some(s) => J::span(s),
                None => J::Null,
            },
        ),
    ])
}

fn message_json(m: &Message) -> J {
    let headers = m
        .headers
        .iter()
        .map(|h| {
            J::Obj(vec![
                ("name", J::str(&h.name)),
                ("value", J::str(&h.value)),
                ("line_span", J::span(h.line_span)),
                ("name_span", J::span(h.name_span)),
                ("value_span", J::span(h.value_span)),
            ])
        })
        .collect();
    J::Obj(vec![
        ("kind", J::str(m.kind.label())),
        ("raw_len", J::Num(m.raw_len as u64)),
        ("body_start", J::Num(m.body_start as u64)),
        ("start_line", start_line_json(&m.start_line)),
        ("headers", J::Arr(headers)),
        ("body", body_json(&m.body)),
    ])
}

/// Serialize a full analysis to pretty-printed JSON.
pub fn to_json(analysis: &Analysis) -> String {
    let value = J::Obj(vec![
        ("message", message_json(&analysis.message)),
        (
            "findings",
            J::Arr(analysis.findings.iter().map(finding_json).collect()),
        ),
    ]);
    let mut out = String::new();
    write(&value, 0, &mut out);
    out.push('\n');
    out
}

/// Serialize only the findings (used by `plainwire lint --json`).
pub fn findings_to_json(findings: &[Finding]) -> String {
    let value = J::Arr(findings.iter().map(finding_json).collect());
    let mut out = String::new();
    write(&value, 0, &mut out);
    out.push('\n');
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;
    use crate::message::ParseMode;

    fn json_req(raw: &[u8]) -> String {
        to_json(&analyze(raw, ParseMode::Request))
    }

    #[test]
    fn escapes_special_characters() {
        let mut s = String::new();
        escape("a\"b\\c\nd\te", &mut s);
        assert_eq!(s, "\"a\\\"b\\\\c\\nd\\te\"");
    }

    #[test]
    fn braces_are_balanced() {
        let out = json_req(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello");
        let opens = out.matches('{').count();
        let closes = out.matches('}').count();
        assert_eq!(opens, closes);
        let ob = out.matches('[').count();
        let cb = out.matches(']').count();
        assert_eq!(ob, cb);
    }

    #[test]
    fn contains_top_level_keys() {
        let out = json_req(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(out.contains("\"message\""));
        assert!(out.contains("\"findings\""));
        assert!(out.contains("\"start_line\""));
        assert!(out.contains("\"kind\": \"request\""));
    }

    #[test]
    fn spans_render_inline_as_two_numbers() {
        let out = json_req(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n");
        assert!(out.contains("\"span\": [0, 14]"), "got: {out}");
    }

    #[test]
    fn findings_carry_code_and_severity() {
        let out = json_req(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n");
        assert!(out.contains("\"code\": \"PW001\""));
        assert!(out.contains("\"severity\": \"error\""));
    }

    #[test]
    fn declared_len_is_null_for_chunked() {
        let out = json_req(b"POST / HTTP/1.1\r\nHost: h\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nhello\r\n0\r\n\r\n");
        assert!(out.contains("\"declared_len\": null"));
        assert!(out.contains("\"framing\": \"chunked\""));
    }
}
