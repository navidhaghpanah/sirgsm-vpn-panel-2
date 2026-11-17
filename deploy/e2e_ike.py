#!/usr/bin/env python3
"""Opt-in root functional test: isolated strongSwan client → installed gateway.

Uses a disposable network/mount namespace and account; leaves the host's client
network settings and certificate trust stores untouched. Carrier test is separate.
"""
import json
import os
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path
import vici
import e2e
from e2e import run,wait_for
from common import database,get

def main():
    if os.geteuid()!=0:raise SystemExit('Run as root')
    e2e.login()
    body={'name':'qa-ike-'+str(int(time.time())),'enabled':True,'quota_gb':1,'protocols':['ikev2'],'expires':None}
    uid=e2e.api('/users',body)['id'];ns='sirgsm-ike-qa';host='sg-ike-host';peer='sg-ike-peer';proc=None
    try:
        wait_for(lambda:next((u for u in e2e.api('/dashboard')['users'] if u['id']==uid and u['provisioned']),None))
        with database() as db:
            user=dict(db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone());ip=get(db,'server_ip')
        run('ip','netns','add',ns);run('ip','link','add',host,'type','veth','peer','name',peer)
        run('ip','link','set',peer,'netns',ns);run('ip','addr','add','10.86.0.1/30','dev',host);run('ip','link','set',host,'up')
        run('ip','-n',ns,'addr','add','10.86.0.2/30','dev',peer);run('ip','-n',ns,'link','set','lo','up');run('ip','-n',ns,'link','set',peer,'up');run('ip','-n',ns,'route','add','default','via','10.86.0.1')
        with tempfile.TemporaryDirectory(prefix='sirgsm-ike-',dir='/run') as tmp:
            folder=Path(tmp)
            conf='''charon-systemd {
 load_modular = yes
 plugins {
  include /etc/strongswan.d/charon/*.conf
  vici { socket = unix:///run/charon.vici
  }
 }
}
'''
            (folder/'strongswan.conf').write_text(conf)
            log=(folder/'charon.log').open('w')
            # The shell text is fixed; the temporary path is a positional argument.
            proc=subprocess.Popen(['ip','netns','exec',ns,'unshare','--mount','--propagation','private','sh','-c','mount --bind "$1" /run; exec env STRONGSWAN_CONF=/run/strongswan.conf /usr/sbin/charon-systemd','sh',tmp],stdout=log,stderr=log)
            wait_for(lambda:(folder/'charon.vici').exists(),15)
            def session():
                sock=socket.socket(socket.AF_UNIX);sock.settimeout(20);sock.connect(str(folder/'charon.vici'));return vici.Session(sock)
            session().load_cert({'type':'X509','flag':'CA','data':Path('/etc/separ/ike-ca.pem').read_bytes()})
            session().load_shared({'id':'qa-eap','type':'EAP','owners':[user['cn']],'data':user['password'].encode()})
            session().load_conn({'qa':{'version':'2','local_addrs':['10.86.0.2'],'remote_addrs':['10.86.0.1'],'vips':['0.0.0.0'],'proposals':['aes256-sha256-modp2048'],'local':{'auth':'eap-mschapv2','id':user['cn'],'eap_id':user['cn']},'remote':{'auth':'pubkey','id':ip},'children':{'qa-internet':{'remote_ts':['0.0.0.0/0'],'esp_proposals':['aes256gcm16']}}}})
            messages=list(session().initiate({'child':'qa-internet','timeout':'15000'}))
            sas=list(session().list_sas())
            assert sas,'No IKE SA was established'
            dest=run('getent','ahostsv4','api.ipify.org').split()[0]
            actual=run('ip','netns','exec',ns,'curl','-fsS','--max-time','15','--resolve',f'api.ipify.org:443:{dest}','https://api.ipify.org')
            assert actual==ip,'Unexpected IKEv2 egress'
            blocked=subprocess.run(['ip','netns','exec',ns,'curl','-fsS','--max-time','3','http://169.254.169.254/latest/meta-data/'],capture_output=True)
            assert blocked.returncode!=0,'Metadata accessible through IKEv2'
            wait_for(lambda:next((u for u in e2e.api('/dashboard')['users'] if u['id']==uid and u['usage'].get('ikev2',0)>0),None),20)
            print('IKEv2: EAP authentication, certificate trust, encrypted egress, metadata isolation and metering passed',flush=True)
            body['enabled']=False;e2e.api('/users/'+uid,body,'PUT')
            wait_for(lambda:len(list(session().list_sas()))==0,20)
            print('IKEv2: disabling the account terminated its active SA',flush=True)
            proc.terminate();proc.wait(timeout=10);proc=None;log.close()
    finally:
        if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
        subprocess.run(['ip','netns','del',ns],capture_output=True);subprocess.run(['ip','link','del',host],capture_output=True)
        e2e.api('/users/'+uid,method='DELETE')

if __name__=='__main__':main()
