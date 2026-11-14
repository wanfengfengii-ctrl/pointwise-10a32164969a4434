"""Business verification for response_capture: body attribution and wire
boundary checks over the fixture captures plus targeted edge cases.

Runs the preserved baseline (checks.py) first, then the capture suite.
Every case feeds real captured bytes through response_capture.Parser.
"""

import os
import subprocess
import sys

from fixtures import REQUESTS, pipelined, tunnel, split_bytes
from response_capture import Parser, WireError

ROOT = os.path.dirname(os.path.abspath(__file__))
CASES = 0


def ok(note):
    global CASES
    CASES += 1
    print("ok %2d  %s" % (CASES, note))


def run(raw, methods, width=None):
    """Feed raw (optionally in width-sized slices) and finish; return events."""
    parser = Parser(list(methods))
    events = []
    chunks = [raw] if width is None else list(split_bytes(raw, width))
    for chunk in chunks:
        events.extend(parser.feed(chunk))
    events.extend(parser.finish())
    return events


def expect_error(raw, methods=("GET",), width=None, note=""):
    """A WireError must be raised and must permanently fail the parser."""
    parser = Parser(list(methods))
    chunks = [raw] if width is None else list(split_bytes(raw, width))
    try:
        for chunk in chunks:
            parser.feed(chunk)
        parser.finish()
    except WireError:
        pass
    else:
        raise AssertionError("no WireError: " + note)
    for again in (lambda: parser.feed(b"x"), parser.finish):
        try:
            again()
        except WireError:
            pass
        else:
            raise AssertionError("failure not permanent: " + note)
    ok(note)


def normalized(events):
    """Merge consecutive data/tunnel events of one request (chunking may vary)."""
    merged = []
    for ev in events:
        if (ev["type"] in ("data", "tunnel") and merged
                and merged[-1]["type"] == ev["type"]
                and merged[-1]["request"] == ev["request"]):
            merged[-1]["payload"] += ev["payload"]
        else:
            merged.append(dict(ev))
    return merged


def bodies_of(events):
    """Reassemble the decoded body attributed to each request index."""
    bodies = {}
    for ev in events:
        if ev["type"] == "data":
            bodies[ev["request"]] = bodies.get(ev["request"], b"") + ev["payload"]
    return bodies


# -- baseline ---------------------------------------------------------------

def baseline():
    proc = subprocess.run([sys.executable, "checks.py"], cwd=ROOT,
                          capture_output=True, text=True)
    assert proc.returncode == 0, proc.stderr
    assert "HTTP1_CAPTURE_FIXTURE_OK" in proc.stdout
    ok("baseline checks.py preserved and passing")


# -- fixture attribution ----------------------------------------------------

EXACT_PIPELINED = [
    {"type": "headers", "request": 0, "status": 100,
     "fields": [(b"X-Hint", b"a")]},
    {"type": "headers", "request": 0, "status": 200,
     "fields": [(b"Content-Length", b"999")]},
    {"type": "end", "request": 0},
    {"type": "headers", "request": 1, "status": 200,
     "fields": [(b"Transfer-Encoding", b"chunked")]},
    {"type": "data", "request": 1, "payload": b"abc"},
    {"type": "data", "request": 1, "payload": b"de"},
    {"type": "trailers", "request": 1, "fields": [(b"X-Checksum", b"yes")]},
    {"type": "end", "request": 1},
    {"type": "headers", "request": 2, "status": 200,
     "fields": [(b"Content-Length", b"4, 4")]},
    {"type": "data", "request": 2, "payload": b"last"},
    {"type": "end", "request": 2},
]

NORMALIZED_PIPELINED = [
    ev if ev["type"] != "data" or ev["request"] != 1 else
    {"type": "data", "request": 1, "payload": b"abcde"}
    for ev in EXACT_PIPELINED
    if not (ev["type"] == "data" and ev["request"] == 1
            and ev["payload"] == b"de")
]


def fixture_attribution():
    raw = pipelined()
    events = run(raw, REQUESTS)
    assert events == EXACT_PIPELINED, events
    # The informational 100 and the HEAD response carry no body; the chunked
    # body is de-framed to abcde and attributed to request 1, the fixed body
    # 'last' to request 2.
    assert bodies_of(events) == {1: b"abcde", 2: b"last"}, events
    # Every possible split width reproduces identical attribution.
    for width in range(1, len(raw) + 1):
        again = run(raw, REQUESTS, width)
        assert normalized(again) == NORMALIZED_PIPELINED, (width, again)
    ok("pipelined fixture: 100/HEAD/chunked+trailers/fixed attribution, "
       "identical across all %d split widths" % len(raw))


def fixture_tunnel():
    expected = [
        {"type": "headers", "request": 0, "status": 200, "fields": []},
        {"type": "end", "request": 0},
        {"type": "tunnel", "request": 0, "payload": b"\x00HTTP/not-http\r\n"},
    ]
    assert run(tunnel(), ["CONNECT"]) == expected
    for width in range(1, len(tunnel()) + 1):
        assert normalized(run(tunnel(), ["CONNECT"], width)) == expected, width
    # The HTTP-looking bytes after the CONNECT 200 are never parsed, and the
    # tunnel switch exempts requests that never got a response.
    events = run(tunnel(), ["CONNECT", "GET", "GET"])
    assert normalized(events) == expected, events
    ok("tunnel fixture: opaque bytes after CONNECT 200, remaining methods exempt")


# -- no-body and informational modes ----------------------------------------

def no_body_modes():
    # HEAD: Content-Length 999/5 creates no body; the next response is parsed
    # at the same input position. 204/304 ignore valid framing headers too.
    events = run(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\n"
                 b"HTTP/1.1 204 No Content\r\n\r\n", ["HEAD", "GET"])
    assert events == [
        {"type": "headers", "request": 0, "status": 200,
         "fields": [(b"Content-Length", b"5")]},
        {"type": "end", "request": 0},
        {"type": "headers", "request": 1, "status": 204, "fields": []},
        {"type": "end", "request": 1},
    ], events
    events = run(b"HTTP/1.1 304 Not Modified\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n", ["GET"])
    assert [ev["type"] for ev in events] == ["headers", "end"], events
    events = run(b"HTTP/1.1 204 No Content\r\nContent-Length: 3\r\n\r\n", ["GET"])
    assert [ev["type"] for ev in events] == ["headers", "end"], events
    ok("HEAD/204/304: no body regardless of valid framing headers")


def informational():
    raw = (b"HTTP/1.1 100 Continue\r\n\r\n"
           b"HTTP/1.1 150 Odd\r\nX-A: 1\r\n\r\n"
           b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
    events = run(raw, ["GET"])
    assert [ev["type"] for ev in events] == ["headers", "headers", "headers", "end"]
    assert [ev.get("status") for ev in events[:3]] == [100, 150, 200]
    assert all(ev["request"] == 0 for ev in events), events
    # An informational response with a valid Content-Length still has no body:
    # the following bytes are the next response, not 5 body bytes.
    events = run(b"HTTP/1.1 100 x\r\nContent-Length: 5\r\n\r\n"
                 b"HTTP/1.1 204 y\r\n\r\n", ["GET"])
    assert [ev.get("status") for ev in events if ev["type"] == "headers"] == [100, 204]
    ok("informational 1xx: headers only, request not consumed, no body")


# -- body framing modes ------------------------------------------------------

def eof_body():
    parser = Parser(["GET"])
    assert parser.feed(b"HTTP/1.1 200 OK\r\n\r\nhe") == [
        {"type": "headers", "request": 0, "status": 200, "fields": []},
        {"type": "data", "request": 0, "payload": b"he"},
    ]
    assert parser.feed(b"llo") == [
        {"type": "data", "request": 0, "payload": b"llo"}]
    # finish() completes the EOF-delimited body and returns the needed end.
    assert parser.finish() == [{"type": "end", "request": 0}]
    assert parser.finish() == []
    ok("EOF-delimited body: streams until finish, end returned by finish")


def fixed_and_chunked_positives():
    # Content-Length zero completes immediately; repeated identical values ok.
    events = run(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                 b"Content-Length: 5, 5\r\n\r\nhello", ["GET"])
    assert bodies_of(events) == {0: b"hello"}, events
    events = run(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", ["GET"])
    assert [ev["type"] for ev in events] == ["headers", "end"], events
    # HEAD accepts even the maximum Content-Length without reading a body.
    events = run(b"HTTP/1.1 200 OK\r\nContent-Length: 9223372036854775807\r\n\r\n",
                 ["HEAD"])
    assert [ev["type"] for ev in events] == ["headers", "end"], events
    # Transfer-Encoding token is case-insensitive with OWS allowed.
    events = run(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: \tChunked \r\n\r\n"
                 b"0\r\n\r\n", ["GET"])
    assert events[1] == {"type": "trailers", "request": 0, "fields": []}, events
    # Chunk extensions: BWS, token and quoted-string values, escapes, and a
    # semicolon inside quotes; extensions on the zero chunk are fine.
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    raw = head + (b'5;a=b;c="d;e\\"f"\r\nhello\r\n'
                  b'5 ; a = b ; c = "x"\r\nworld\r\n'
                  b"007\r\nabcdefg\r\n"
                  b"A\r\n0123456789\r\n"
                  b"0;fin=yes\r\n\r\n")
    events = run(raw, ["GET"])
    assert bodies_of(events) == {0: b"hello" b"world" b"abcdefg" b"0123456789"}, events
    assert events[-2] == {"type": "trailers", "request": 0, "fields": []}, events
    # Chunked response pipelined with the next response in one feed.
    events = run(head + b"1\r\nz\r\n0\r\n\r\nHTTP/1.1 204 y\r\n\r\n",
                 ["GET", "GET"])
    assert [ev["type"] for ev in events] == [
        "headers", "data", "trailers", "end", "headers", "end"], events
    ok("fixed/chunked framing: CL repeats, TE case, extensions, pipelining")


# -- tunnel modes ------------------------------------------------------------

def tunnel_modes():
    # 101 switches to an opaque tunnel; HTTP-looking bytes stay unparsed.
    events = run(b"HTTP/1.1 101 Switching Protocols\r\nUpgrade: h2c\r\n\r\n"
                 b"HTTP/1.1 999 Bogus\r\n", ["GET"])
    assert events == [
        {"type": "headers", "request": 0, "status": 101,
         "fields": [(b"Upgrade", b"h2c")]},
        {"type": "end", "request": 0},
        {"type": "tunnel", "request": 0, "payload": b"HTTP/1.1 999 Bogus\r\n"},
    ], events
    # Non-2xx CONNECT follows ordinary response rules (real body here).
    events = run(b"HTTP/1.1 407 Proxy Authentication Required\r\n"
                 b"Content-Length: 3\r\n\r\nabc", ["CONNECT"])
    assert bodies_of(events) == {0: b"abc"}, events
    # Any 2xx CONNECT response (here 204) is a tunnel switch.
    events = run(b"HTTP/1.1 204 x\r\n\r\nzz", ["CONNECT"])
    assert events[-1] == {"type": "tunnel", "request": 0, "payload": b"zz"}, events
    ok("101 and CONNECT 2xx: tunnel switch; CONNECT 407 stays ordinary")


# -- field syntax ------------------------------------------------------------

def field_preservation():
    events = run(b"HTTP/1.1 200 OK\r\n"
                 b"X-A: 1\r\nx-a: 2\r\nX-A:  3 \t\r\n"
                 b"Empty:\r\nObs: \x80\xff\r\n"
                 b"Content-Length: 0\r\n\r\n", ["GET"])
    assert events[0]["fields"] == [
        (b"X-A", b"1"), (b"x-a", b"2"), (b"X-A", b"3"),
        (b"Empty", b""), (b"Obs", b"\x80\xff"), (b"Content-Length", b"0"),
    ], events
    # Reason phrase variants: absent, empty after SP, HTAB inside.
    for line in (b"HTTP/1.1 204\r\n\r\n",
                 b"HTTP/1.1 204 \r\n\r\n",
                 b"HTTP/1.1 204 \tNo Content\r\n\r\n"):
        assert [ev["type"] for ev in run(line, ["GET"])] == ["headers", "end"]
    ok("fields: case/order/duplicates preserved, OWS stripped, obs-text kept")


def empty_feeds_harmless():
    parser = Parser(["GET"])
    assert parser.feed(b"") == []
    assert parser.feed(b"HTTP/1.1 204 y\r\n\r\n") != []
    assert parser.feed(b"") == []
    assert parser.finish() == []
    ok("empty feed is harmless before, during and after the capture")


# -- error cases --------------------------------------------------------------

def status_line_errors():
    expect_error(b"HTTP/1.0 200 OK\r\n\r\n", note="reject HTTP/1.0 status line")
    expect_error(b"HTTP/1.1 200OK\r\n\r\n", note="reject missing SP before reason")
    expect_error(b"HTTP/1.1 20 OK\r\n\r\n", note="reject two-digit status")
    expect_error(b"HTTP/1.1 2000 OK\r\n\r\n", note="reject four-digit status")
    expect_error(b"HTTP/1.1 099 x\r\n\r\n", note="reject status below 100")
    expect_error(b"HTTP/1.1 600 x\r\n\r\n", note="reject status above 599")
    expect_error(b"HTTP/1.1  200 OK\r\n\r\n", note="reject double SP in status line")
    expect_error(b"HTTP/1.1 200 OK\n", note="reject bare LF in status line")
    expect_error(b"HTTP/1.1 200 O\x01K\r\n\r\n", note="reject control in reason")
    expect_error(b"HTTP/1.1 200 OK\rX: y\r\n\r\n", note="reject malformed CR in line")


def header_errors():
    expect_error(b"HTTP/1.1 200 OK\r\nX Y: v\r\n\r\n", note="reject bad field name")
    expect_error(b"HTTP/1.1 200 OK\r\n: v\r\n\r\n", note="reject empty field name")
    expect_error(b"HTTP/1.1 200 OK\r\nX\r\n\r\n", note="reject field without colon")
    expect_error(b"HTTP/1.1 200 OK\r\nX: a\x00b\r\n\r\n", note="reject NUL in value")
    expect_error(b"HTTP/1.1 200 OK\r\nX: a\x7fb\r\n\r\n", note="reject DEL in value")
    expect_error(b"HTTP/1.1 200 OK\r\nX: a\r\n b\r\n\r\n", note="reject folded line")
    expect_error(b"HTTP/1.1 200 OK\r\nX: a\nY: b\r\n\r\n", note="reject bare LF in headers")


def framing_errors():
    both = b"Content-Length: 1\r\nTransfer-Encoding: chunked\r\n\r\n"
    expect_error(b"HTTP/1.1 200 OK\r\n" + both, note="reject TE+CL on GET")
    expect_error(b"HTTP/1.1 200 OK\r\n" + both, methods=["HEAD"],
                 note="reject TE+CL on HEAD")
    expect_error(b"HTTP/1.1 204 x\r\n" + both, note="reject TE+CL on 204")
    expect_error(b"HTTP/1.1 101 x\r\n" + both, note="reject TE+CL on 101")
    expect_error(b"HTTP/1.1 100 x\r\n" + both + b"HTTP/1.1 204 y\r\n\r\n",
                 note="reject TE+CL on informational")
    expect_error(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n"
                 b"Content-Length: 6\r\n\r\n", note="reject disagreeing CL lines")
    expect_error(b"HTTP/1.1 200 OK\r\nContent-Length: 5,6\r\n\r\n",
                 note="reject disagreeing CL items")
    for bad, why in ((b"5,", "empty CL item"), (b",5", "leading empty CL item"),
                     (b"5,,5", "middle empty CL item"), (b"-5", "signed CL"),
                     (b"+5", "plus-signed CL"), (b"5x", "nondecimal CL"),
                     (b"", "empty CL value"),
                     (b"9223372036854775808", "CL above 2**63-1")):
        expect_error(b"HTTP/1.1 200 OK\r\nContent-Length: " + bad + b"\r\n\r\n",
                     note="reject " + why)
    expect_error(b"HTTP/1.1 200 OK\r\nContent-Length: 9x\r\n\r\n",
                 methods=["HEAD"], note="framing checked before HEAD no-body mode")
    for bad, why in ((b"gzip", "unknown coding"),
                     (b"chunked, gzip", "chunked not last/alone"),
                     (b"gzip, chunked", "coding list"),
                     (b"chunked chunked", "two tokens one line"),
                     (b"", "empty TE value")):
        expect_error(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: " + bad + b"\r\n\r\n",
                     note="reject TE " + why)
    expect_error(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n"
                 b"Transfer-Encoding: chunked\r\n\r\n",
                 note="reject chunked on two TE lines")


def chunk_errors():
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    for bad, why in (
            (b"3;=x\r\n", "extension without name"),
            (b"3;x=\r\n", "extension without value"),
            (b'3;x="abc\r\n', "unterminated quoted string"),
            (b'3;x="a\x01b"\r\n', "control octet in quoted string"),
            (b'3;x="a\\\x01b"\r\n', "bad quoted-pair escape"),
            (b"3x\r\n", "garbage after chunk size"),
            (b"3 \r\n", "trailing BWS without extension"),
            (b"8000000000000000\r\n", "chunk size above 2**63-1"),
            (b"\r\n", "empty chunk-size line")):
        expect_error(head + bad, note="reject " + why)
    # Exactly N data bytes then CRLF: the CR inside the count is data here.
    expect_error(head + b"3\r\nab\r\n0\r\n\r\n",
                 note="chunk data shorter than declared shifts CRLF check")
    expect_error(head + b"3\r\nabcXX", note="reject missing chunk-data CRLF")
    expect_error(head + b"3\r\nab", note="reject truncated chunk data at EOF")
    expect_error(head + b"3", note="reject truncated chunk-size line at EOF")
    expect_error(head + b"0\r\nContent-Length: 1\r\n\r\n",
                 note="reject Content-Length in trailers")
    expect_error(head + b"0\r\nTransfer-Encoding: chunked\r\n\r\n",
                 note="reject Transfer-Encoding in trailers")
    expect_error(head + b"0\r\nX Y: 1\r\n\r\n", note="reject bad trailer line")


def truncation_and_count_errors():
    expect_error(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab",
                 note="reject truncated fixed body at EOF")
    expect_error(b"HTTP/1.1 200 OK\r\nContent-Len",
                 note="reject truncated header section at EOF")
    expect_error(b"HTTP/1.1 20", note="reject truncated status line at EOF")
    expect_error(b"", note="reject capture with all requests unanswered")
    expect_error(b"HTTP/1.1 204 y\r\n\r\n", methods=["GET", "GET"],
                 note="reject capture with one request unanswered")
    expect_error(b"HTTP/1.1 200 OK\r\n\r\nabc", methods=["GET", "GET"],
                 note="reject EOF body leaving requests unanswered")
    expect_error(b"HTTP/1.1 204 x\r\n\r\nx",
                 note="reject bytes after all requests consumed")
    expect_error(b"HTTP/1.1 204 x\r\n\r\nHTTP/1.1 204 y\r\n\r\n",
                 note="reject extra response after all requests consumed")


def failure_and_sealing_semantics():
    # Events delivered before the failure stay delivered; nothing is emitted
    # for the malformed section, and the parser never recovers.
    parser = Parser(["GET", "GET"])
    first = parser.feed(b"HTTP/1.1 204 y\r\n\r\n")
    assert [ev["type"] for ev in first] == ["headers", "end"], first
    try:
        parser.feed(b"wibble\r\n\r\n")
    except WireError:
        pass
    else:
        raise AssertionError("expected WireError")
    assert [ev["type"] for ev in first] == ["headers", "end"]
    # A malformed trailer section emits no trailers event; streamed body kept.
    parser = Parser(["GET"])
    head = b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n"
    first = parser.feed(head + b"1\r\nz\r\n")
    assert [ev["type"] for ev in first] == ["headers", "data"], first
    try:
        parser.feed(b"0\r\nBad Trailer\r\n\r\n")
    except WireError:
        pass
    else:
        raise AssertionError("expected WireError")
    # finish() seals: repeated finish returns [], later feed is an error.
    parser = Parser(["GET"])
    parser.feed(b"HTTP/1.1 204 y\r\n\r\n")
    assert parser.finish() == []
    assert parser.finish() == []
    try:
        parser.feed(b"x")
    except WireError:
        pass
    else:
        raise AssertionError("feed after finish not rejected")
    assert parser.finish() == []
    # A failed finish (truncated body) permanently fails the parser too.
    parser = Parser(["GET"])
    parser.feed(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nab")
    for op in (parser.finish, lambda: parser.feed(b"x"), parser.finish):
        try:
            op()
        except WireError:
            pass
        else:
            raise AssertionError("failure not permanent after bad finish")
    ok("WireError is permanent; delivered events kept; finish seals the parser")


def streaming_retention():
    # A 1 MiB fixed body streams through without being retained whole.
    total = 1 << 20
    parser = Parser(["GET"])
    head = b"HTTP/1.1 200 OK\r\nContent-Length: %d\r\n\r\n" % total
    assert [ev["type"] for ev in parser.feed(head)] == ["headers"]
    got, piece = 0, b"x" * 8192
    for _ in range(total // len(piece)):
        events = parser.feed(piece)
        assert len(parser._line) == 0 and not parser._fields
        # The slice completing the body also carries the end event.
        assert [ev["type"] for ev in events] in (["data"], ["data", "end"])
        got += sum(len(ev["payload"]) for ev in events if ev["type"] == "data")
    assert got == total
    assert parser.finish() == []
    # Same for chunked framing with slices that straddle chunk boundaries.
    body = b"".join(b"%x\r\n" % 16384 + b"y" * 16384 + b"\r\n"
                    for _ in range(64)) + b"0\r\n\r\n"
    parser = Parser(["GET"])
    parser.feed(head.replace(b"Content-Length: %d" % total,
                             b"Transfer-Encoding: chunked"))
    got = 0
    for piece in split_bytes(body, 8192):
        for ev in parser.feed(piece):
            if ev["type"] == "data":
                got += len(ev["payload"])
        assert len(parser._line) <= 32  # only a partial chunk-size line
    assert got == 64 * 16384
    assert [ev["type"] for ev in parser.finish()] == []
    ok("1 MiB bodies stream incrementally; no whole-body retention")


def main():
    baseline()
    fixture_attribution()
    fixture_tunnel()
    no_body_modes()
    informational()
    eof_body()
    fixed_and_chunked_positives()
    tunnel_modes()
    field_preservation()
    empty_feeds_harmless()
    status_line_errors()
    header_errors()
    framing_errors()
    chunk_errors()
    truncation_and_count_errors()
    failure_and_sealing_semantics()
    streaming_retention()
    print("CAPTURE_VERIFY_OK (%d checks)" % CASES)


if __name__ == "__main__":
    main()
