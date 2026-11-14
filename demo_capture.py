"""Real extraction demo: run response_capture.Parser over the captured
fixture bytes and print exactly what the data collector would receive.
"""

from fixtures import REQUESTS, pipelined, tunnel, split_bytes
from response_capture import Parser


def format_event(ev):
    kind = ev["type"]
    if kind == "headers":
        return "headers  request=%d status=%d fields=%r" % (
            ev["request"], ev["status"], ev["fields"])
    if kind == "data":
        return "data     request=%d payload=%r" % (ev["request"], ev["payload"])
    if kind == "trailers":
        return "trailers request=%d fields=%r" % (ev["request"], ev["fields"])
    if kind == "tunnel":
        return "tunnel   request=%d payload=%r" % (ev["request"], ev["payload"])
    return "end      request=%d" % ev["request"]


def show(events):
    for ev in events:
        print("  " + format_event(ev))


def merged(events):
    """Collapse consecutive data/tunnel events of one request."""
    out = []
    for ev in events:
        if (ev["type"] in ("data", "tunnel") and out
                and out[-1]["type"] == ev["type"]
                and out[-1]["request"] == ev["request"]):
            out[-1]["payload"] += ev["payload"]
        else:
            out.append(dict(ev))
    return out


def main():
    raw = pipelined()
    print("== pipelined capture: methods=%s, %d bytes, fed in one call =="
          % (REQUESTS, len(raw)))
    parser = Parser(REQUESTS)
    events = parser.feed(raw) + parser.finish()
    show(events)
    bodies = {}
    for ev in events:
        if ev["type"] == "data":
            bodies[ev["request"]] = bodies.get(ev["request"], b"") + ev["payload"]
    print("  reassembled bodies per request: %r" % (bodies,))

    print("== same capture fed byte-at-a-time (chunking may vary) ==")
    replay = Parser(REQUESTS)
    streamed = []
    for piece in split_bytes(raw, 1):
        streamed.extend(replay.feed(piece))
    streamed.extend(replay.finish())
    show(merged(streamed))
    print("  identical after merging data chunks: %s"
          % (merged(streamed) == merged(events)))

    print("== CONNECT capture: methods=['CONNECT'], %d bytes ==" % len(tunnel()))
    parser = Parser(["CONNECT"])
    show(parser.feed(tunnel()))
    show(parser.finish())
    print("CAPTURE_DEMO_OK")


if __name__ == "__main__":
    main()
