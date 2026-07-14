//! Human-readable rendering of an [`Analysis`]: the annotated breakdown printed
//! by `plainwire inspect` and the findings-only view printed by `plainwire
//! lint`. Output is plain text by default; ANSI colour is opt-in so piped
//! output stays byte-stable and greppable.

use crate::findings::{Counts, Finding, Severity};
use crate::message::{escape_bytes, Analysis, Framing, MessageKind};

/// ANSI styling, toggled off for pipes and `--no-color`.
#[derive(Clone, Copy)]
pub struct Palette {
    enabled: bool,
}

impl Palette {
    pub fn new(enabled: bool) -> Self {
        Palette { enabled }
    }

    fn paint(&self, code: &str, text: &str) -> String {
        if self.enabled {
            format!("\x1b[{code}m{text}\x1b[0m")
        } else {
            text.to_string()
        }
    }

    fn dim(&self, text: &str) -> String {
        self.paint("2", text)
    }
    fn bold(&self, text: &str) -> String {
        self.paint("1", text)
    }
    fn severity(&self, sev: Severity, text: &str) -> String {
        match sev {
            Severity::Error => self.paint("1;31", text),
            Severity::Warn => self.paint("33", text),
            Severity::Info => self.paint("36", text),
        }
    }
}

fn truncate(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_string()
    } else {
        let cut: String = s.chars().take(max.saturating_sub(1)).collect();
        format!("{cut}\u{2026}")
    }
}

/// Findings sorted most-severe first, preserving discovery order within a
/// severity (a stable sort).
fn sorted(findings: &[Finding]) -> Vec<&Finding> {
    let mut v: Vec<&Finding> = findings.iter().collect();
    v.sort_by(|a, b| b.severity.rank().cmp(&a.severity.rank()));
    v
}

fn summary_line(counts: Counts) -> String {
    format!(
        "findings: {} error(s), {} warn(s), {} info",
        counts.error, counts.warn, counts.info
    )
}

/// Render the findings block (used by both `inspect` and `lint`).
pub fn render_findings(findings: &[Finding], pal: &Palette) -> String {
    let mut out = String::new();
    out.push_str(&summary_line(Counts::of(findings)));
    out.push('\n');
    if findings.is_empty() {
        out.push_str("  (no framing ambiguities detected)\n");
        return out;
    }
    for f in sorted(findings) {
        out.push_str(&format!(
            "  {:<5}  {}  {}\n",
            pal.severity(f.severity, f.severity.label()),
            pal.bold(f.code),
            f.slug
        ));
        out.push_str(&format!("         {}\n", f.detail));
        if let Some(span) = f.span {
            out.push_str(&pal.dim(&format!("         at bytes {span}\n")));
        }
    }
    out
}

/// Render the full annotated breakdown for `plainwire inspect`.
pub fn render(analysis: &Analysis, pal: &Palette) -> String {
    let m = &analysis.message;
    let mut out = String::new();

    out.push_str(&format!(
        "{} — {}, {} header(s), {} byte(s)\n\n",
        pal.bold("plainwire"),
        m.kind.label(),
        m.headers.len(),
        m.raw_len
    ));

    // --- start-line ---------------------------------------------------------
    out.push_str(&format!(
        "start-line  {}\n",
        pal.dim(&format!("[{}]", m.start_line.span))
    ));
    let sl = &m.start_line;
    match m.kind {
        MessageKind::Request => {
            out.push_str(&format!("  method   {}\n", sl.method()));
            out.push_str(&format!("  target   {}\n", sl.target()));
            out.push_str(&format!("  version  {}\n", sl.version()));
        }
        MessageKind::Response => {
            out.push_str(&format!("  version  {}\n", sl.resp_version()));
            out.push_str(&format!("  status   {}\n", sl.status()));
            out.push_str(&format!("  reason   {}\n", sl.reason()));
        }
    }

    // --- headers ------------------------------------------------------------
    out.push_str(&format!("\nheaders ({})\n", m.headers.len()));
    for h in &m.headers {
        let value = truncate(&escape_bytes(h.value.as_bytes()), 80);
        out.push_str(&format!(
            "  {}  {}: {}\n",
            pal.dim(&format!("[{}]", h.line_span)),
            h.name,
            value
        ));
    }

    // --- body ---------------------------------------------------------------
    let b = &m.body;
    out.push_str(&format!("\nbody  {}\n", pal.dim(&format!("[{}]", b.span))));
    out.push_str(&format!("  framing   {}\n", b.framing.label()));
    if let Some(n) = b.declared_len {
        out.push_str(&format!("  declared  {n} byte(s)\n"));
    }
    out.push_str(&format!("  decoded   {} byte(s)\n", b.decoded_len));
    if b.framing == Framing::Chunked {
        out.push_str(&format!("  chunks    {}\n", b.chunks.len()));
    }
    out.push_str(&format!(
        "  complete  {}\n",
        if b.complete { "yes" } else { "no" }
    ));

    // --- framing note -------------------------------------------------------
    out.push('\n');
    out.push_str(&format!("framing: {}\n", framing_note(b.framing)));

    // --- findings -----------------------------------------------------------
    out.push('\n');
    out.push_str(&render_findings(&analysis.findings, pal));
    out
}

fn framing_note(framing: Framing) -> String {
    match framing {
        Framing::Empty => "empty (no Content-Length or Transfer-Encoding; no body)".to_string(),
        Framing::ContentLength => "content-length (fixed-size body)".to_string(),
        Framing::Chunked => {
            "chunked (Transfer-Encoding wins; a Content-Length here would be ignored by a \
             conforming server)"
                .to_string()
        }
        Framing::UntilClose => {
            "until-close (response body ends when the connection closes)".to_string()
        }
        Framing::Ambiguous => {
            "AMBIGUOUS (the framing headers contradict each other; two servers may read \
             different body lengths)"
                .to_string()
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::analyze;
    use crate::message::ParseMode;

    fn render_req(raw: &[u8], color: bool) -> String {
        let a = analyze(raw, ParseMode::Request);
        render(&a, &Palette::new(color))
    }

    #[test]
    fn renders_all_sections() {
        let out = render_req(
            b"POST /login HTTP/1.1\r\nHost: h\r\nContent-Length: 5\r\n\r\nhello",
            false,
        );
        assert!(out.contains("plainwire — request"));
        assert!(out.contains("start-line"));
        assert!(out.contains("method   POST"));
        assert!(out.contains("target   /login"));
        assert!(out.contains("headers (2)"));
        assert!(out.contains("Content-Length: 5"));
        assert!(out.contains("framing   content-length"));
        assert!(out.contains("findings: 0 error"));
    }

    #[test]
    fn clean_message_reports_no_ambiguities() {
        let out = render_req(b"GET / HTTP/1.1\r\nHost: h\r\n\r\n", false);
        assert!(out.contains("no framing ambiguities detected"));
    }

    #[test]
    fn no_color_output_has_no_escape_bytes() {
        let out = render_req(b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n", false);
        assert!(
            !out.contains('\x1b'),
            "no-color output must not contain ESC"
        );
        assert!(out.contains("PW001"));
    }

    #[test]
    fn findings_are_sorted_error_first() {
        // A message with both an error (PW001) and an info (PW012): the error
        // must be listed before the info.
        let raw = b"POST / HTTP/1.1\r\nHost: h\r\nContent-Length: 6\r\nTransfer-Encoding: chunked\r\n\r\n5;x=1\r\nhello\r\n0\r\n\r\n";
        let out = render_req(raw, false);
        let e = out.find("PW001").unwrap();
        let i = out.find("PW012").unwrap();
        assert!(e < i, "error should sort before info");
    }
}
