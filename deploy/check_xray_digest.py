import hashlib
import re
import sys
from pathlib import Path

archive,digest=map(Path,sys.argv[1:])
actual=hashlib.sha256(archive.read_bytes()).hexdigest()
matches=re.findall(r'(?i)(?<![0-9a-f])[0-9a-f]{64}(?![0-9a-f])',digest.read_text())
if actual.lower() not in [s.lower() for s in matches]:
    raise SystemExit('Xray SHA-256 verification failed')
print('Xray SHA-256 verified')
