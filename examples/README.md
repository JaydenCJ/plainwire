# plainwire examples

Four raw HTTP/1.1 request captures with real CRLF line endings. Feed them to
`plainwire` from the repository root to see the annotated breakdown and the
framing findings. (These files were produced by `plainwire craft`; you can
regenerate them the same way — see the command under each one.)

| File | What it is | Regenerate |
|---|---|---|
| `clean-post.http` | A well-formed `POST` with a Content-Length body; zero findings | `plainwire craft -X POST --host example.test --target /login --body 'user=alice&action=login'` |
| `cl-te-desync.http` | A CL.TE gadget: Content-Length and Transfer-Encoding both present, with a smuggled trailing byte | `plainwire craft --smuggle cl.te --host example.test --target /admin` |
| `te-te-obfuscated.http` | A TE.TE gadget: two Transfer-Encoding headers, one obfuscated (`xchunked`) | `plainwire craft --smuggle te.te --host example.test --target /admin` |
| `bare-lf-desync.http` | A Transfer-Encoding header terminated by a bare LF instead of CRLF | `plainwire craft --smuggle bare-lf --host example.test --target /admin` |

## Try it

```bash
# Annotated, byte-level breakdown of the clean request.
plainwire inspect examples/clean-post.http

# Lint the CL.TE gadget; this exits 1 because of the desync.
plainwire lint examples/cl-te-desync.http

# See the exact bytes, region-labelled.
plainwire hexdump examples/te-te-obfuscated.http

# Lint every example and report which ones fail the gate.
for f in examples/*.http; do
  plainwire lint "$f" >/dev/null && echo "OK   $f" || echo "FAIL $f"
done
```

The `.http` files use CRLF (`\r\n`) exactly as they would on the wire, so
`bare-lf-desync.http` is genuinely different at the byte level — that is the
whole point of the tool. Open them with `plainwire hexdump` if your editor
hides the difference.
