//! Byte ranges into the raw message buffer.
//!
//! Every structural element plainwire recognizes (the start-line, each header,
//! each chunk, the body) carries a [`Span`] so the annotator, the hex dump and
//! individual findings can point at the exact bytes they describe. Offsets are
//! absolute into the original input; `start` is inclusive, `end` exclusive.

/// A half-open byte range `[start, end)` into the raw message buffer.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Span {
    pub start: usize,
    pub end: usize,
}

impl Span {
    /// Construct a span. `end` is clamped to be at least `start` so a span is
    /// never negative-length even if a caller passes a stale cursor.
    pub fn new(start: usize, end: usize) -> Self {
        Span {
            start,
            end: end.max(start),
        }
    }

    /// An empty span anchored at `at`.
    pub fn empty(at: usize) -> Self {
        Span { start: at, end: at }
    }

    /// Number of bytes covered.
    pub fn len(&self) -> usize {
        self.end - self.start
    }

    /// Whether the span covers zero bytes.
    pub fn is_empty(&self) -> bool {
        self.end == self.start
    }

    /// Whether `offset` falls inside the half-open range.
    pub fn contains(&self, offset: usize) -> bool {
        offset >= self.start && offset < self.end
    }

    /// Slice the given buffer with this span, clamped to the buffer length so
    /// a truncated message can never panic.
    pub fn slice<'a>(&self, buf: &'a [u8]) -> &'a [u8] {
        let end = self.end.min(buf.len());
        let start = self.start.min(end);
        &buf[start..end]
    }
}

impl std::fmt::Display for Span {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}..{}", self.start, self.end)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn len_and_empty() {
        assert_eq!(Span::new(4, 10).len(), 6);
        assert!(Span::empty(3).is_empty());
        assert!(!Span::new(0, 1).is_empty());
    }

    #[test]
    fn end_is_clamped_to_start() {
        // A stale cursor that runs past the start must not produce a negative
        // length; it collapses to an empty span instead.
        let s = Span::new(10, 4);
        assert_eq!(s.start, 10);
        assert_eq!(s.end, 10);
        assert!(s.is_empty());
    }

    #[test]
    fn contains_is_half_open() {
        let s = Span::new(2, 5);
        assert!(!s.contains(1));
        assert!(s.contains(2));
        assert!(s.contains(4));
        assert!(!s.contains(5));
    }

    #[test]
    fn slice_clamps_to_buffer() {
        let buf = b"hello";
        assert_eq!(Span::new(1, 3).slice(buf), b"el");
        // A span past the end clamps rather than panicking.
        assert_eq!(Span::new(3, 99).slice(buf), b"lo");
        assert_eq!(Span::new(99, 120).slice(buf), b"");
    }
}
