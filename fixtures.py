"""Captured HTTP/1 response streams; no receiving parser."""
REQUESTS=['HEAD','GET','GET']
def pipelined():
    return (b'HTTP/1.1 100 Continue\r\nX-Hint: a\r\n\r\n'
      b'HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n'
      b'HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n'
      b'3;tag="x;y"\r\nabc\r\n2\r\nde\r\n0\r\nX-Checksum: yes\r\n\r\n'
      b'HTTP/1.1 200 OK\r\nContent-Length: 4, 4\r\n\r\nlast')
def tunnel():
    return b'HTTP/1.1 200 Connection established\r\n\r\n\x00HTTP/not-http\r\n'
def split_bytes(raw,width):
    for pos in range(0,len(raw),width):yield raw[pos:pos+width]
