# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.0] - 2026-07-12

### Added

- Byte-by-byte HTTP/1.1 parser: start-line (request or response, auto-detected), header block with an exact byte span for every field name, value and line, and a framed body.
- RFC 9112 §6 body-length precedence: Transfer-Encoding with a final `chunked` coding wins; otherwise a single valid Content-Length applies; contradictions are reported rather than guessed.
- Chunked scanner: per-chunk sizes and spans, chunk extensions, hex validation, truncated-body and missing-terminator detection, and trailer counting.
- 20 stable finding codes (`PW001`–`PW020`) covering both-CL-TE, duplicate and conflicting Content-Length, duplicate Transfer-Encoding, non-chunked-final and obfuscated codings, whitespace-before-colon, bare LF / bare CR, invalid Content-Length, chunk anomalies, missing/multiple Host, obsolete line folding and trailing/incomplete bodies.
- `plainwire inspect`: annotated breakdown with per-region byte offsets, optional ANSI colour, `--json`, and `--hex`.
- `plainwire lint`: findings-only view with `--fail-on error|warn|info|never` driving the exit code, for CI.
- `plainwire hexdump`: classic `offset | hex | ascii` dump with a per-row structural region label.
- `plainwire craft`: build raw requests with real CRLFs and an auto Content-Length or chunked body, plus five known desync gadgets (`cl.te`, `te.cl`, `te.te`, `space-colon`, `bare-lf`).
- `plainwire codes`: the full finding catalog and gadget list.
- Hand-rolled, dependency-free JSON serializer for machine-readable output.
- Zero runtime dependencies (std-only) and no network access at any point.
- Test suite: 80 unit tests, 10 CLI integration tests, and `scripts/smoke.sh`.

[0.1.0]: https://github.com/JaydenCJ/plainwire/releases/tag/v0.1.0
