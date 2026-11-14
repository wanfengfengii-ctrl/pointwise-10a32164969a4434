"""Incremental HTTP/1.1 response-capture parser.

Reads captured server-to-client HTTP/1.1 bytes from a single connection and
attributes responses, decoded bodies, trailers and upgrade tunnels to the
ordered client request methods supplied by the caller.  Standard library
only; no sockets, HTTP client/server, TLS, compression or persistence.

Interface:
    Parser(methods)    methods: nonempty list of uppercase method tokens
    parser.feed(bytes) -> [event, ...]   (incremental, empty feed harmless)
    parser.finish()    -> [event, ...]   (marks EOF, seals the parser)
    WireError          malformed input; the failure is permanent

Events:
    {'type': 'headers',  'request': i, 'status': int,
     'fields': [(name_bytes, value_bytes), ...]}
    {'type': 'data',     'request': i, 'payload': bytes}
    {'type': 'trailers', 'request': i, 'fields': [(name_bytes, value_bytes), ...]}
    {'type': 'end',      'request': i}
    {'type': 'tunnel',   'request': i, 'payload': bytes}

Between feed calls the parser retains only the current incomplete line, the
current incomplete field section and framing counters; body bytes are
streamed out as data/tunnel events and never buffered whole.
"""

__all__ = ["WireError", "Parser"]

_MAX_INT64 = (1 << 63) - 1

_TOKEN = frozenset(b"!#$%&'*+-.^_`|~"
                   b"0123456789"
                   b"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
                   b"abcdefghijklmnopqrstuvwxyz")
_DIGIT = frozenset(b"0123456789")
_HEXDIG = frozenset(b"0123456789abcdefABCDEF")
_OWS = b" \t"
_HTAB = 0x09
_SP = 0x20
_DQUOTE = 0x22
_BACKSLASH = 0x5C
_SEMICOLON = 0x3B
_EQUALS = 0x3D


class WireError(Exception):
    """The captured bytes violate the HTTP/1.1 wire rules."""


def _visible_octet(c):
    # HTAB / SP..~ / obs-text; everything else is a rejected control octet.
    return c == _HTAB or 0x20 <= c <= 0x7E or c >= 0x80


def _parse_status_line(line):
    """Validate exactly 'HTTP/1.1 SP 3DIGIT [SP reason]'; return the code."""
    if not line.startswith(b"HTTP/1.1 "):
        raise WireError("malformed status line: %r" % (line,))
    rest = line[9:]
    if len(rest) < 3 or any(c not in _DIGIT for c in rest[:3]):
        raise WireError("malformed status code: %r" % (line,))
    if len(rest) > 3:
        if rest[3] != _SP:
            raise WireError("malformed status line: %r" % (line,))
        if any(not _visible_octet(c) for c in rest[4:]):
            raise WireError("control octet in reason phrase: %r" % (line,))
    status = int(rest[:3])
    if not 100 <= status <= 599:
        raise WireError("status code out of range: %d" % status)
    return status


def _parse_field(line):
    """Parse one header/trailer line into (name_bytes, value_bytes)."""
    colon = line.find(b":")
    if colon <= 0:
        raise WireError("malformed field line: %r" % (line,))
    name = line[:colon]
    if any(c not in _TOKEN for c in name):
        raise WireError("malformed field name: %r" % (line,))
    value = line[colon + 1:]
    if any(not _visible_octet(c) for c in value):
        raise WireError("control octet in field value: %r" % (line,))
    return bytes(name), bytes(value.strip(_OWS))


def _skip_quoted_string(line, pos):
    """pos is just past the opening quote; return index past the close."""
    n = len(line)
    while True:
        if pos >= n:
            raise WireError("unterminated quoted string")
        c = line[pos]
        if c == _DQUOTE:
            return pos + 1
        if c == _BACKSLASH:
            pos += 1
            if pos >= n or not _visible_octet(line[pos]):
                raise WireError("malformed quoted pair")
            pos += 1
            continue
        if not _visible_octet(c):
            raise WireError("control octet in quoted string")
        pos += 1


def _parse_chunk_size(line):
    """Validate '1*HEXDIG *(BWS ";" BWS token [BWS "=" BWS (token/quoted)])'."""
    n = len(line)
    if n == 0 or line[0] not in _HEXDIG:
        raise WireError("malformed chunk-size line: %r" % (line,))
    size = 0
    i = 0
    while i < n and line[i] in _HEXDIG:
        size = size * 16 + int(chr(line[i]), 16)
        if size > _MAX_INT64:
            raise WireError("chunk size exceeds 2**63-1")
        i += 1
    while i < n:
        while i < n and line[i] in (_SP, _HTAB):
            i += 1
        if i >= n or line[i] != _SEMICOLON:
            raise WireError("garbage after chunk size: %r" % (line,))
        i += 1
        while i < n and line[i] in (_SP, _HTAB):
            i += 1
        start = i
        while i < n and line[i] in _TOKEN:
            i += 1
        if i == start:
            raise WireError("missing chunk-extension name: %r" % (line,))
        mark = i
        while i < n and line[i] in (_SP, _HTAB):
            i += 1
        if i < n and line[i] == _EQUALS:
            i += 1
            while i < n and line[i] in (_SP, _HTAB):
                i += 1
            if i < n and line[i] == _DQUOTE:
                i = _skip_quoted_string(line, i + 1)
            else:
                start = i
                while i < n and line[i] in _TOKEN:
                    i += 1
                if i == start:
                    raise WireError("missing chunk-extension value: %r" % (line,))
        else:
            i = mark
    return size


def _framing(fields):
    """Validate Content-Length/Transfer-Encoding; return (length, chunked)."""
    lengths = []
    te_tokens = []
    te_seen = False
    for name, value in fields:
        lname = name.lower()
        if lname == b"content-length":
            for item in value.split(b","):
                item = item.strip(_OWS)
                if not item:
                    raise WireError("empty Content-Length item")
                if any(c not in _DIGIT for c in item):
                    raise WireError("non-decimal Content-Length: %r" % (item,))
                number = int(item)
                if number > _MAX_INT64:
                    raise WireError("Content-Length exceeds 2**63-1")
                lengths.append(number)
        elif lname == b"transfer-encoding":
            te_seen = True
            te_tokens.extend(item.strip(_OWS) for item in value.split(b","))
    if lengths and te_seen:
        raise WireError("Content-Length combined with Transfer-Encoding")
    if lengths and any(number != lengths[0] for number in lengths):
        raise WireError("conflicting Content-Length values")
    if te_seen and (len(te_tokens) != 1 or te_tokens[0].lower() != b"chunked"):
        raise WireError("unsupported Transfer-Encoding")
    return (lengths[0] if lengths else None), te_seen


class Parser:
    """Incremental parser for one captured server-to-client byte stream."""

    _STATUS = 0      # between responses: expecting a status line
    _HEADERS = 1     # inside a header field section
    _CHUNK_SIZE = 2  # expecting a chunk-size line
    _CHUNK_DATA = 3  # inside chunk data
    _CHUNK_CRLF = 4  # expecting the CRLF after chunk data
    _TRAILERS = 5    # inside a trailer field section
    _FIXED = 6       # inside a Content-Length body
    _EOF = 7         # body runs until finish()
    _TUNNEL = 8      # opaque upgraded/CONNECT tunnel

    def __init__(self, methods):
        self._methods = list(methods)
        self._next = 0            # request index the next final response consumes
        self._state = self._STATUS
        self._line = bytearray()  # current incomplete line only
        self._fields = []         # current incomplete field section only
        self._status = 0
        self._remaining = 0       # fixed/chunk body bytes still owed
        self._crlf_pos = 0        # progress matching CRLF after chunk data
        self._tunnel_request = 0
        self._failed = False
        self._sealed = False

    def feed(self, data):
        if self._failed:
            raise WireError("parser is permanently failed")
        if self._sealed:
            raise WireError("parser is sealed after finish")
        try:
            return self._feed(data)
        except WireError:
            self._failed = True
            raise

    def finish(self):
        if self._failed:
            raise WireError("parser is permanently failed")
        if self._sealed:
            return []
        try:
            events = self._finish()
        except WireError:
            self._failed = True
            raise
        self._sealed = True
        return events

    # -- internal ---------------------------------------------------------

    def _feed(self, data):
        events = []
        i = 0
        n = len(data)
        while i < n:
            state = self._state
            if state in (self._STATUS, self._HEADERS,
                         self._CHUNK_SIZE, self._TRAILERS):
                if state == self._STATUS and self._next >= len(self._methods):
                    raise WireError("response bytes after all requests consumed")
                j = data.find(b"\n", i)
                if j < 0:
                    self._line += data[i:]
                    i = n
                    continue
                line = self._line + data[i:j]
                del self._line[:]
                i = j + 1
                if not line.endswith(b"\r"):
                    raise WireError("bare LF in line")
                self._handle_line(bytes(line[:-1]), events)
            elif state == self._FIXED or state == self._CHUNK_DATA:
                take = min(self._remaining, n - i)
                events.append({"type": "data", "request": self._next,
                               "payload": bytes(data[i:i + take])})
                self._remaining -= take
                i += take
                if self._remaining == 0:
                    if state == self._FIXED:
                        self._end_response(events)
                    else:
                        self._state = self._CHUNK_CRLF
            elif state == self._CHUNK_CRLF:
                while i < n and self._crlf_pos < 2:
                    if data[i] != b"\r\n"[self._crlf_pos]:
                        raise WireError("missing CRLF after chunk data")
                    self._crlf_pos += 1
                    i += 1
                if self._crlf_pos == 2:
                    self._crlf_pos = 0
                    self._state = self._CHUNK_SIZE
            elif state == self._EOF:
                events.append({"type": "data", "request": self._next,
                               "payload": bytes(data[i:])})
                i = n
            else:  # self._TUNNEL
                events.append({"type": "tunnel", "request": self._tunnel_request,
                               "payload": bytes(data[i:])})
                i = n
        return events

    def _handle_line(self, line, events):
        state = self._state
        if state == self._STATUS:
            self._status = _parse_status_line(line)
            self._fields = []
            self._state = self._HEADERS
        elif state == self._HEADERS:
            if line == b"":
                self._complete_headers(events)
            else:
                self._fields.append(_parse_field(line))
        elif state == self._CHUNK_SIZE:
            size = _parse_chunk_size(line)
            if size == 0:
                self._fields = []
                self._state = self._TRAILERS
            else:
                self._remaining = size
                self._state = self._CHUNK_DATA
        else:  # self._TRAILERS
            if line == b"":
                for name, _value in self._fields:
                    if name.lower() in (b"content-length", b"transfer-encoding"):
                        raise WireError("forbidden trailer field: %r" % (name,))
                events.append({"type": "trailers", "request": self._next,
                               "fields": list(self._fields)})
                self._fields = []
                self._end_response(events)
            else:
                self._fields.append(_parse_field(line))

    def _complete_headers(self, events):
        status = self._status
        fields = self._fields
        self._fields = []
        # Framing header syntax is checked for every response, before any
        # body-mode selection (so TE+CL is an error even for HEAD/204/101).
        length, chunked = _framing(fields)
        index = self._next
        if 100 <= status <= 199 and status != 101:
            # Informational: headers only, no request consumed.
            events.append({"type": "headers", "request": index,
                           "status": status, "fields": list(fields)})
            self._state = self._STATUS
            return
        method = self._methods[index]
        events.append({"type": "headers", "request": index,
                       "status": status, "fields": list(fields)})
        if status == 101 or (method == "CONNECT" and 200 <= status <= 299):
            # Switch to an opaque tunnel right after the header section;
            # framing headers create no HTTP body here.
            self._tunnel_request = index
            self._end_response(events)
            self._state = self._TUNNEL
            return
        if method == "HEAD" or status == 204 or status == 304:
            self._end_response(events)
            return
        if chunked:
            self._state = self._CHUNK_SIZE
        elif length is not None:
            if length == 0:
                self._end_response(events)
            else:
                self._remaining = length
                self._state = self._FIXED
        else:
            self._state = self._EOF

    def _end_response(self, events):
        events.append({"type": "end", "request": self._next})
        self._next += 1
        self._state = self._STATUS

    def _finish(self):
        events = []
        if self._state == self._EOF:
            # EOF-delimited body completes now; end is still needed.
            self._end_response(events)
            if self._next != len(self._methods):
                raise WireError("capture ended with unanswered requests")
        elif self._state == self._TUNNEL:
            pass  # tunnel switching exempts any remaining methods
        elif self._state == self._STATUS and not self._line:
            if self._next != len(self._methods):
                raise WireError("capture ended with unanswered requests")
        else:
            raise WireError("capture ended mid-response")
        return events
