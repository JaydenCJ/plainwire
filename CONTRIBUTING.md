# Contributing to plainwire

Thanks for your interest in improving plainwire. Issues, discussions and pull requests are all welcome.

## Getting started

Prerequisites: Rust 1.75 or newer (stable toolchain).

```bash
git clone https://github.com/JaydenCJ/plainwire.git
cd plainwire
cargo build
cargo test
bash scripts/smoke.sh
```

`scripts/smoke.sh` builds the binary and drives the real CLI end to end — craft a gadget, inspect it, lint it, hexdump it — asserting on the output and exit codes. It finishes in a few seconds and must print `SMOKE OK`.

## Before you open a pull request

1. `cargo fmt` — formatting is enforced.
2. `cargo clippy --all-targets -- -D warnings` — clippy must be clean.
3. `cargo test` — the unit tests and the CLI integration tests must pass.
4. `bash scripts/smoke.sh` — the smoke test must print `SMOKE OK`.
5. Add tests for behavior changes. Parsing, framing and chunk logic live in pure modules (`parser`, `framing`, `chunked`) that are easy to unit-test; please keep it that way.

## Ground rules

- Keep dependencies minimal. plainwire has zero runtime dependencies (std only); adding one needs a clear justification in the PR description, because a byte-accurate parser must not inherit another library's framing decisions.
- No network calls, ever. plainwire reads bytes and describes them; it does not open sockets or phone home.
- Code comments and doc comments are written in English.
- Framing behavior must stay honest: report what a message *is*, name the ambiguity, and never silently "fix" it. New heuristics belong behind a finding code, not in the parser's happy path.

## Reporting bugs

Please include the exact input bytes (a `plainwire hexdump` of the message is ideal, since it is unambiguous about whitespace and line endings), the `plainwire --version` output, and what you expected versus what was reported. Framing bugs are far easier to fix from a concrete byte sequence than from a description.

## Security

plainwire is an offline analysis tool, but if you find a security issue (for example a parser crash or an input that makes it hang), please do not open a public issue. Use GitHub's private vulnerability reporting on this repository instead.
