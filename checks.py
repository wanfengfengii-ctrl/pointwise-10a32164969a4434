import json,sys,hashlib
from fixtures import REQUESTS,pipelined,tunnel,split_bytes
raw=pipelined()
assert b'Content-Length: 999' in raw and raw.endswith(b'last')
assert b'3;tag="x;y"\r\nabc' in raw and b'X-Checksum: yes' in raw
assert b''.join(split_bytes(raw,1))==raw and b''.join(split_bytes(raw,7))==raw
assert tunnel().endswith(b'\x00HTTP/not-http\r\n')
print('HTTP1_CAPTURE_FIXTURE_OK')
if len(sys.argv)>1:print(json.dumps({'requests':REQUESTS,'bytes':len(raw),'sha256':hashlib.sha256(raw).hexdigest()}))
