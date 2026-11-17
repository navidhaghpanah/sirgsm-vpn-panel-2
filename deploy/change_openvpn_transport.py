#!/usr/bin/env python3
"""Change the single managed OpenVPN listener; preserve quota and certificate policy."""
import argparse
import os
import subprocess
import sys
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from common import database

def main():
    parser=argparse.ArgumentParser()
    parser.add_argument('transport',choices=['tcp','udp'])
    args=parser.parse_args()
    if os.geteuid()!=0:raise PermissionError('Run as root')
    os.umask(0o077)
    config=Path('/etc/openvpn/server/amazon.conf')
    template=Path('/etc/separ/openvpn-client-template')
    marker=Path('/etc/separ/openvpn-transport')
    originals={p:p.read_bytes() if p.exists() else None for p in (config,template,marker)}
    backup=Path('/var/backups/sirgsm');backup.mkdir(mode=0o700,parents=True,exist_ok=True)
    import time
    stamp=time.time_ns()
    for p,data in originals.items():
        if data is not None:
            target=backup/f'{stamp}-{p.name}'
            target.write_bytes(data);target.chmod(0o600)
    text=config.read_text()
    lines=[line for line in text.splitlines() if not line.startswith(('proto ','tcp-nodelay','explicit-exit-notify'))]
    lines+=['proto '+('udp' if args.transport=='udp' else 'tcp-server'),
            'explicit-exit-notify 1' if args.transport=='udp' else 'tcp-nodelay']
    client=template.read_text()
    client='\n'.join(('proto '+('udp' if args.transport=='udp' else 'tcp-client')) if line.startswith('proto ') else line for line in client.splitlines())+'\n'
    try:
        config.write_text('\n'.join(lines)+'\n');template.write_text(client)
        marker.write_text(args.transport+'\n');marker.chmod(0o600)
        subprocess.run(['systemctl','restart','openvpn-server@amazon'],check=True)
        subprocess.run(['systemctl','is-active','--quiet','openvpn-server@amazon'],check=True)
        with database() as db:db.execute('UPDATE users SET provisioned=0 WHERE deleted=0')
    except Exception:
        for p,data in originals.items():
            if data is None:p.unlink(missing_ok=True)
            else:p.write_bytes(data)
        subprocess.run(['systemctl','restart','openvpn-server@amazon'],check=False)
        raise
    print('OpenVPN transport:',args.transport,'— download and import updated profiles.')

if __name__=='__main__':main()
