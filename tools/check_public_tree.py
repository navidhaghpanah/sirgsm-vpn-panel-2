"""Fail publication/CI on accidental runtime artifacts or obvious private keys."""
import re
import subprocess
from pathlib import Path

root=Path(__file__).resolve().parents[1]
files=subprocess.check_output(['git','ls-files','-z'],cwd=root).decode().split('\0')
bad=[]
for relative in filter(None,files):
    path=root/relative
    if path.suffix.lower() in {'.pem','.key','.ovpn','.mobileconfig','.cer','.db','.sqlite','.sqlite3'} or relative.endswith(('-admin.txt','-credentials.txt')):
        bad.append(relative+': runtime/private artifact');continue
    if not path.is_file() or path.suffix.lower() in {'.png','.jpg','.woff','.woff2'}:continue
    text=path.read_text(errors='replace')
    patterns=[r'-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{30,}',r'gh[pousr]_[A-Za-z0-9]{25,}',r'github_pat_[A-Za-z0-9_]{30,}']
    if any(re.search(pattern,text) for pattern in patterns):bad.append(relative+': potential secret')
if bad:raise SystemExit('\n'.join(bad))
print('Tracked public source contains no forbidden runtime artifacts or recognized private-key/token patterns.')
