#!/usr/bin/env python3
"""Opt-in functional checks on an installed test server. Never publishes credentials.

Creates one disposable account, tests all Xray transports and a real OpenVPN
network namespace, then checks quota/expiry revocation and deletes the account.
Run as root: /opt/sirgsm-runtime/bin/python /opt/separ/deploy/e2e.py
"""
import base64
import datetime as dt
import hashlib
import json
import os
import re
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from common import EXPORTS,PROTOCOLS,active,database,get

BASE='http://127.0.0.1:8099/api'
TOKEN='';CSRF=''

def api(path,body=None,method=None):
    req=urllib.request.Request(BASE+path,data=json.dumps(body).encode() if body is not None else None,
          method=method,headers={'Content-Type':'application/json','Cookie':TOKEN,'X-CSRF-Token':CSRF})
    with urllib.request.urlopen(req,timeout=20) as r:return json.load(r)

def run(*args,**kwargs):return subprocess.check_output(args,text=True,stderr=subprocess.STDOUT,**kwargs).strip()

def wait_for(fn,timeout=40):
    end=time.monotonic()+timeout
    while time.monotonic()<end:
        try:
            result=fn()
            if result:return result
        except (OSError,KeyError):pass
        time.sleep(1)
    raise AssertionError('Timed out waiting for test condition')

def xray_test(user,settings,protocol,folder):
    ports=settings['ports'];ip=settings['server_ip']
    stream={'network':'tcp','security':'none'}
    if protocol=='reality':
        r=settings['reality'];out={'protocol':'vless','settings':{'vnext':[{'address':'127.0.0.1','port':ports[protocol],'users':[{'id':user['uuid'],'encryption':'none','flow':'xtls-rprx-vision'}]}]}}
        stream.update(security='reality',realitySettings={'serverName':r['sni'],'fingerprint':'chrome','password':r['public'],'shortId':r['sid']})
    elif protocol=='shadowsocks':
        key=base64.b64encode(hashlib.sha256(user['password'].encode()).digest()).decode()
        out={'protocol':'shadowsocks','settings':{'servers':[{'address':'127.0.0.1','port':ports[protocol],'method':'2022-blake3-aes-256-gcm','password':settings['ss_master']+':'+key}]}}
    elif protocol=='trojan':
        out={'protocol':'trojan','settings':{'servers':[{'address':'127.0.0.1','port':ports[protocol],'password':user['password']}]}}
        stream.update(security='tls',tlsSettings={'serverName':ip})
    else:
        out={'protocol':'vmess','settings':{'vnext':[{'address':'127.0.0.1','port':ports[protocol],'users':[{'id':user['uuid'],'security':'auto','alterId':0}]}]}}
        stream.update(network='ws',security='tls',tlsSettings={'serverName':ip},wsSettings={'path':'/sirgsm-vmess','headers':{'Host':ip}})
    out['streamSettings']=stream
    config={'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':10818,'protocol':'socks','settings':{'udp':True}}],'outbounds':[out]}
    path=folder/'xray.json';path.write_text(json.dumps(config));path.chmod(0o600)
    with (folder/(protocol+'.log')).open('w') as log:
        proc=subprocess.Popen(['/usr/local/bin/xray','run','-c',str(path)],stdout=log,stderr=log)
        try:
            time.sleep(.6)
            actual=run('curl','-fsS','--max-time','15','--socks5-hostname','127.0.0.1:10818','https://api.ipify.org')
            assert actual==ip,(protocol,'incorrect egress')
            blocked=subprocess.run(['curl','-fsS','--max-time','3','--socks5-hostname','127.0.0.1:10818','http://169.254.169.254/latest/meta-data/'],capture_output=True)
            assert blocked.returncode!=0,'Metadata must not be accessible'
        except Exception as error:
            print(log.name+': '+(getattr(error,'output','') or str(error)),flush=True)
            raise
        finally:proc.terminate();proc.wait(timeout=5)
    print(protocol+': tunnel, egress and metadata isolation passed',flush=True)

def openvpn_test(user,folder,ip):
    ns='sirgsm-qa';host='sg-qa-host';peer='sg-qa-peer';proc=None;second=None
    def clean():
        nonlocal proc
        if second and second.poll() is None:second.terminate();second.wait(timeout=10)
        if proc and proc.poll() is None:proc.terminate();proc.wait(timeout=10)
        subprocess.run(['ip','netns','del',ns],capture_output=True)
        subprocess.run(['ip','link','del',host],capture_output=True)
    try:
        run('ip','netns','add',ns);run('ip','link','add',host,'type','veth','peer','name',peer)
        run('ip','link','set',peer,'netns',ns);run('ip','addr','add','10.84.0.1/30','dev',host);run('ip','link','set',host,'up')
        run('ip','-n',ns,'addr','add','10.84.0.2/30','dev',peer);run('ip','-n',ns,'link','set','lo','up');run('ip','-n',ns,'link','set',peer,'up');run('ip','-n',ns,'route','add','default','via','10.84.0.1')
        profile=(EXPORTS/user['id']/'openvpn.ovpn').read_text()
        profile=re.sub(r'^remote .+ 2053$','remote 10.84.0.1 2053',profile,flags=re.M)
        path=folder/'qa.ovpn';path.write_text(profile);path.chmod(0o600)
        log=folder/'openvpn.log'
        proc=subprocess.Popen(['ip','netns','exec',ns,'openvpn','--config',str(path),'--remap-usr1','SIGTERM','--log',str(log)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        wait_for(lambda:log.exists() and 'Initialization Sequence Completed' in log.read_text(),25)
        dest=run('getent','ahostsv4','api.ipify.org').split()[0]
        actual=run('ip','netns','exec',ns,'curl','-fsS','--max-time','15','--resolve',f'api.ipify.org:443:{dest}','https://api.ipify.org')
        assert actual==ip
        blocked=subprocess.run(['ip','netns','exec',ns,'curl','-fsS','--max-time','3','http://169.254.169.254/latest/meta-data/'],capture_output=True)
        assert blocked.returncode!=0,'Metadata accessible from OpenVPN'
        print('openvpn: certificate-only tunnel, egress and metadata isolation passed',flush=True)
        second_log=folder/'openvpn-second.log'
        second=subprocess.Popen(['ip','netns','exec',ns,'openvpn','--config',str(path),'--dev','tun-qa2','--route-noexec','--ifconfig-noexec','--remap-usr1','SIGTERM','--log',str(second_log)],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        wait_for(lambda:second_log.exists() and 'Initialization Sequence Completed' in second_log.read_text(),20)
        wait_for(lambda:proc.poll() is not None,15)
        from worker import management
        rows=[line for line in management('status 3').splitlines() if line.startswith('CLIENT_LIST\t'+user['cn']+'\t')]
        assert len(rows)==1,'A certificate must only have one simultaneous connection'
        print('openvpn: importing the same certificate twice leaves one simultaneous connection',flush=True)
    finally:clean()

def login():
    global TOKEN,CSRF
    credential=Path('/root/sirgsm-admin.txt')
    if not credential.exists():credential=Path('/home/ubuntu/separ-admin.txt')
    text=credential.read_text();password=re.search(r'^Password: (.+)$',text,re.M)[1].strip();username=re.search(r'^Username: (.+)$',text,re.M)[1].strip()
    wait_for(lambda:run('curl','-s','-o','/dev/null','--write-out','%{http_code}',BASE+'/session')=='401',30)
    req=urllib.request.Request(BASE+'/login',data=json.dumps({'username':username,'password':password}).encode(),headers={'Content-Type':'application/json'})
    with urllib.request.urlopen(req) as response:
        TOKEN=response.headers['Set-Cookie'].split(';')[0];CSRF=json.load(response)['csrf']

def main():
    if os.geteuid()!=0:raise SystemExit('Root is required for disposable network namespaces')
    login()
    body={'name':'qa-'+str(int(time.time())),'enabled':True,'quota_gb':1,'protocols':list(PROTOCOLS),'expires':None}
    uid=api('/users',body)['id']
    try:
        wait_for(lambda:next((u for u in api('/dashboard')['users'] if u['id']==uid and u['provisioned']),None))
        with database() as db:
            user=dict(db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone())
            settings={key:get(db,key) for key in ['server_ip','ports','reality','ss_master']}
        with tempfile.TemporaryDirectory(prefix='sirgsm-e2e-',dir='/run') as tmp:
            folder=Path(tmp)
            for protocol in ['reality','shadowsocks','trojan','vmess']:xray_test(user,settings,protocol,folder)
            openvpn_test(user,folder,settings['server_ip'])
        result=wait_for(lambda:next((u for u in api('/dashboard')['users'] if u['id']==uid and all(u['usage'].get(p,0)>0 for p in ['reality','shadowsocks','trojan','vmess','openvpn'])),None),25)
        assert result['used']==sum(result['usage'].values())
        print('Shared accounting: sum of five real transport sessions passed',flush=True)
        body['quota_gb']=1e-9
        api('/users/'+uid,body,'PUT')
        def xray_has_user():
            return any(c.get('email','').split('@')[0]==user['cn'] for i in json.loads(Path('/usr/local/etc/xray/config.json').read_text())['inbounds'] for c in i['settings'].get('clients',i['settings'].get('users',[])))
        wait_for(lambda:not xray_has_user() and not Path('/etc/openvpn/ccd',user['cn']).exists(),25)
        assert not Path('/etc/openvpn/ccd',user['cn']).exists()
        assert user['cn'] not in Path('/etc/swanctl/conf.d/separ-users.conf').read_text()
        print('Quota reached: Xray, OpenVPN and IKEv2 credentials revoked',flush=True)
        body['quota_gb']=1;body['expires']=(dt.datetime.now(dt.timezone.utc)+dt.timedelta(seconds=15)).isoformat()
        api('/users/'+uid,body,'PUT')
        wait_for(xray_has_user,12)
        wait_for(lambda:next(u for u in api('/dashboard')['users'] if u['id']==uid)['status']=='expired' and not xray_has_user() and not Path('/etc/openvpn/ccd',user['cn']).exists(),30)
        assert user['cn'] not in Path('/etc/swanctl/conf.d/separ-users.conf').read_text()
        print('Shared expiry: passed',flush=True)
    finally:
        api('/users/'+uid,method='DELETE')
    print('Functional E2E checks completed. IKEv2 network/carrier test is separate.',flush=True)

if __name__=='__main__':main()
