#!/usr/bin/python3
"""Called by OpenVPN after privilege drop; records final data-channel totals."""
import fcntl
import json
import os
import stat

item={'kind':'connect' if os.environ.get('script_type')=='client-connect' else 'disconnect',
      'cn':os.environ.get('common_name',''),
      'remote':os.environ.get('trusted_ip','')+':'+os.environ.get('trusted_port',''),
      'in':int(os.environ.get('bytes_received',0)),
      'out':int(os.environ.get('bytes_sent',0))}
fd=os.open('/var/lib/separ-openvpn/events.jsonl',os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW|os.O_CLOEXEC)
with os.fdopen(fd,'a') as f:
    info=os.fstat(f.fileno())
    if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1:
        raise RuntimeError('Unsafe accounting spool')
    fcntl.flock(f,fcntl.LOCK_EX)
    f.write(json.dumps(item)+'\n'); f.flush(); os.fsync(f.fileno())
