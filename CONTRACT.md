# Response-capture stream and public extraction interface

Input is captured server-to-client HTTP/1.1 bytes from a single connection.
The ordered client request methods are supplied separately, not parsed here.
No sockets, HTTP client/server, TLS, compression, redirects or disk persistence.
Implement response_capture.Parser(methods), feed(bytes)->events, finish()->events.
methods is a finite nonempty list of uppercase method tokens (including HEAD and
CONNECT); feed bytes and constructor types are valid. Empty feed is harmless.
The receiving parser must operate incrementally, not wait for a complete capture.

Events:
 {'type':'headers','request':i,'status':int,'fields':[(name_bytes,value_bytes),...]}
 {'type':'data','request':i,'payload':bytes}
 {'type':'trailers','request':i,'fields':[(name_bytes,value_bytes),...]}
 {'type':'end','request':i}
 {'type':'tunnel','request':i,'payload':bytes}.
Request index i is zero based. Fields preserve original name case, order,
duplicates and raw value octets after stripping leading/trailing SP/HTAB.
Data events carry only decoded transfer-framing payload, not chunk markers.
Empty data/tunnel events are not emitted; chunk boundaries are unrestricted.

Status lines are exactly HTTP/1.1 SP three digits [SP reason] CRLF; status range
100..599. Header lines require nonempty RFC7230 token names and colon, no folded
lines. Value octets may be HTAB, SP..~ or >=128; reject embedded controls.
Reject bare LF and malformed CRLF in lines. End a field section by empty CRLF.

100..199 except 101 are informational: emit headers only and do not consume a
request. A final response consumes one request only at end. HEAD final responses,
204 and 304 have no body regardless of valid framing headers. After such headers
emit end immediately and parse the next response at the same input position.
For all responses, parse/check framing header syntax before selecting body mode.

Content-Length may repeat or contain comma-separated decimal values with OWS;
all nonempty values must be identical, nonnegative and <=2**63-1. Any disagreement,
sign, empty item or nondecimal is error. Header names compare case-insensitively.
Transfer-Encoding is accepted only as exactly one token chunked (case-insensitive
and OWS allowed), across all TE header lines; any other coding/list is error.
A response with both TE and CL is always error, even for HEAD/204/304.
A final ordinary response uses chunked when TE exists, fixed-length when CL
exists, else EOF-delimited. Content-Length zero completes immediately.
Unknown ordinary fields never alter framing.

Chunk-size is one or more hexadecimal digits <=2**63-1 followed by optional
chunk extensions. Extensions follow RFC7230 token or quoted-string rules:
semicolon token [=token|quoted-string], optional BWS around semicolon/equal;
quoted strings allow semicolons and quoted-pair escaping, no bare control bytes.
Reject missing names/values, malformed quotes and garbage. Nonzero chunks require
exactly that many data bytes then CRLF. A zero chunk starts a trailer section;
emit one trailers event (even empty) then end. Trailer field syntax matches
headers, but Content-Length and Transfer-Encoding are forbidden in trailers.
Do not assume feed boundaries coincide with a line, chunk or response boundary.

101 and successful CONNECT (status 200..299) switch to opaque tunnel immediately
after their header section. Emit end for the HTTP response, then tunnel events
for all remaining and subsequent bytes. These bytes are never parsed as HTTP,
even if they resemble a status line; no requirement to validate Upgrade fields.
Other non-2xx CONNECT responses follow ordinary response rules.
For 101/CONNECT, valid framing headers do not create an HTTP body.

finish marks EOF: EOF-delimited body completes then, complete fixed/chunked or
no-body responses already completed; incomplete status/header/fixed/chunked input
is error. A clean capture with some supplied requests still unanswered is also
error; tunnel switching exempts any remaining methods. finish returns end only
where still needed and seals the parser. After success, repeated finish returns
[], and later feed is error. More response bytes after all methods are consumed
are error, except an empty feed. Malformed input raises response_capture.WireError
and permanently fails the parser; all subsequent feed/finish raise WireError.
Previously emitted events remain valid; no event is emitted for a malformed header
section or malformed trailer section. Body already streamed need not be retracted.

Retain only incomplete framing lines/field sections and framing counters between
feed calls; do not hold a complete body/capture or repeatedly concatenate/reparse
prior body bytes. Returned events and caller-owned input are excluded.
fixtures.pipelined() yields 100/200 headers for request0 then end, request1 headers,
body abcde, trailers X-Checksum=yes and end, then request2 headers, body last and end.
Body event chunking may vary. Preserve fixtures.py and checks.py; add the extractor,
business verification and real demonstration; update the existing runtime manifest.
