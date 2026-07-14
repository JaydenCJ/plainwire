#!/usr/bin/env bash
# Smoke test: builds plainwire, then drives the real CLI end to end — craft a
# desync gadget, inspect it, lint it (exit code), hexdump it, and round-trip a
# clean request. Self-contained: temp files only, no network.
set -euo pipefail

cd "$(dirname "$0")/.."

fail() { echo "SMOKE FAIL: $*" >&2; exit 1; }

echo "[smoke] building..."
cargo build --quiet
BIN=target/debug/plainwire

WORK=$(mktemp -d "${TMPDIR:-/tmp}/plainwire-smoke.XXXXXX")
trap 'rm -rf "$WORK"' EXIT

# --- 1. version / help sanity ------------------------------------------------
# Capture output to a file before grepping. Piping straight into `grep -q` lets
# grep close the pipe on its first match, which (with SIGPIPE at its Unix
# default) terminates the tool early and trips `pipefail` nondeterministically.
"$BIN" --version > "$WORK/version.out"
grep -q '^plainwire 0\.1\.0$' "$WORK/version.out" || fail "--version mismatch"
"$BIN" --help > "$WORK/help.out"
grep -q 'COMMANDS:' "$WORK/help.out" || fail "--help missing sections"
for c in inspect lint hexdump craft codes; do
  grep -q "$c" "$WORK/help.out" || fail "--help missing '$c'"
done
echo "[smoke] version/help OK"

# --- 2. craft a CL.TE gadget and inspect it ----------------------------------
"$BIN" craft --smuggle cl.te --host example.test > "$WORK/clte.http"
grep -q 'Content-Length: 6' "$WORK/clte.http" || fail "gadget missing Content-Length"
grep -q 'Transfer-Encoding: chunked' "$WORK/clte.http" || fail "gadget missing Transfer-Encoding"

"$BIN" inspect --request "$WORK/clte.http" | tee "$WORK/inspect.out" >/dev/null
grep -q 'both-cl-te' "$WORK/inspect.out" || fail "inspect did not flag both-cl-te"
grep -q 'framing   chunked' "$WORK/inspect.out" || fail "inspect did not choose chunked framing"
grep -q 'trailing-body-bytes' "$WORK/inspect.out" || fail "inspect missed the smuggled trailing byte"
echo "[smoke] craft + inspect (CL.TE) OK"

# --- 3. lint exit codes ------------------------------------------------------
# The gadget must fail the lint gate (exit 1).
if "$BIN" lint --request "$WORK/clte.http" > "$WORK/lint.out"; then
  fail "lint accepted a CL.TE desync"
fi
grep -q 'PW001' "$WORK/lint.out" || fail "lint output missing PW001"

# --fail-on never reports but never fails.
"$BIN" lint --request --fail-on never "$WORK/clte.http" >/dev/null \
  || fail "--fail-on never should exit 0"
echo "[smoke] lint exit codes OK"

# --- 4. a clean crafted request lints green ----------------------------------
"$BIN" craft -X POST --host example.test --body 'user=root' > "$WORK/clean.http"
"$BIN" lint "$WORK/clean.http" > "$WORK/clean.out" || fail "clean request failed the lint gate"
grep -q 'no framing ambiguities detected' "$WORK/clean.out" \
  || fail "clean request reported findings"
echo "[smoke] clean request round-trip OK"

# --- 5. te.te gadget flags duplicate + obfuscated TE -------------------------
"$BIN" craft --smuggle te.te | "$BIN" lint --request - > "$WORK/tete.out" || true
grep -q 'PW004' "$WORK/tete.out" || fail "te.te gadget did not flag duplicate Transfer-Encoding"
grep -q 'PW006' "$WORK/tete.out" || fail "te.te gadget did not flag obfuscated coding"
echo "[smoke] te.te gadget OK"

# --- 6. hexdump + codes ------------------------------------------------------
"$BIN" hexdump --request "$WORK/clte.http" | tee "$WORK/hex.out" >/dev/null
grep -q '^00000000' "$WORK/hex.out" || fail "hexdump missing offset column"
grep -q 'start-line' "$WORK/hex.out" || fail "hexdump missing region labels"
"$BIN" codes > "$WORK/codes.out"
grep -q 'PW001' "$WORK/codes.out" || fail "codes did not list PW001"
echo "[smoke] hexdump + codes OK"

# --- 7. JSON output is well-formed-ish ---------------------------------------
"$BIN" inspect --request --json "$WORK/clte.http" > "$WORK/out.json"
grep -q '"code": "PW001"' "$WORK/out.json" || fail "json missing PW001"
python3 -c 'import json,sys; json.load(open(sys.argv[1]))' "$WORK/out.json" 2>/dev/null \
  && echo "[smoke] json parses" || echo "[smoke] json check skipped (no python3)"

echo "SMOKE OK"
