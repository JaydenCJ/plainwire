# HTTP/1.1 message framing, and how plainwire reasons about it

This is the model plainwire implements. It is a working summary of RFC 9112
(HTTP/1.1 message syntax) §6, written from the point of view of "where can two
implementations disagree about how long the body is?" — because every such
disagreement is a request-smuggling (desync) opportunity.

## The body-length algorithm

Given a request or response, the body length is determined by the **first**
rule below that applies (RFC 9112 §6.3):

1. **Transfer-Encoding is present.** If the final transfer coding is `chunked`,
   the body is chunked-framed and Content-Length is ignored. If the final
   coding is *not* `chunked`, then for a request the length is undeterminable
   and the server ought to respond `400`; leniency here is a desync surface.
   plainwire reports `PW005` (`te-not-chunked-final`).
2. **Content-Length is present and valid.** The body is exactly that many
   bytes. If it resolves to more than one value — duplicate fields, or a comma
   list like `5, 6` — the message is unrecoverable (`PW002`, `PW003`). If it is
   not a bare non-negative decimal, it is invalid (`PW010`).
3. **Neither is present.** A request has no body; a response body runs until the
   connection closes.

The critical rule: **a message carrying both Content-Length and
Transfer-Encoding is malformed** (RFC 9112 §6.1). A conforming recipient uses
Transfer-Encoding and must remove Content-Length before forwarding. When a
front-end proxy and a back-end server pick different headers, the bytes one of
them leaves unread become the beginning of a *smuggled* request. plainwire
always reports this as `PW001` (`both-cl-te`).

## Where parsers drift apart

Real deployments chain multiple HTTP implementations (CDN, reverse proxy,
application server), and they do not all parse identically. The classic
divergences, each with a plainwire finding:

| Divergence | Vector | Finding |
|---|---|---|
| One hop uses CL, another uses TE | CL.TE / TE.CL | `PW001` |
| Duplicate Content-Length, taken first vs last | header selection | `PW002` |
| Two Transfer-Encoding headers, one obfuscated | TE.TE | `PW004`, `PW006` |
| `chunked` hidden by odd casing/spelling | `xchunked`, `chunked` + junk | `PW006` |
| Space before the colon strips a header for some | `Transfer-Encoding :` | `PW007` |
| Bare LF accepted as a terminator by some | `...\n` instead of `...\r\n` | `PW008` |
| Obsolete line folding unfolded differently | leading SP/HTAB continuation | `PW019` |

## Line endings are part of the framing

RFC 9112 §2.2 defines the terminator as CRLF but permits a recipient to accept
a bare LF and ignore a preceding CR. plainwire treats a `\n` with no `\r` as a
distinct byte sequence (`PW008`) and a `\r` that is not part of a CRLF as a bare
CR (`PW009`), because a header that a strict CRLF parser ignores can still take
effect one hop downstream. This is why the tool works on **bytes**, not on a
normalized string: `Transfer-Encoding: chunked\n` and
`Transfer-Encoding: chunked\r\n` are different messages.

## Chunked bodies

A chunked body is a sequence of `chunk-size [ ";" extension ] CRLF chunk-data
CRLF`, ended by a `0`-size chunk, optional trailer fields, and a final CRLF.
plainwire's scanner records each chunk's size and byte spans and reports a
non-hex size or a size that does not line up with the following CRLF (`PW011`),
chunk extensions (`PW012`), a truncated body (`PW018`), and a body that never
reached its `0`-size terminator (`PW020`). Any bytes left after the terminator
are surfaced as `PW017` (`trailing-body-bytes`) — on a request boundary those
bytes are, by definition, the start of the next request.
