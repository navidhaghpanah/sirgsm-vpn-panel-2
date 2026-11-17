"""Privileged, fixed-function protocol reconciler. No shell commands from HTTP."""
import csv
import base64
import fcntl
import hashlib
import json
import os
import plistlib
import queue
import re
import shutil
import socket
import stat
import subprocess
import threading
import time
import uuid
from pathlib import Path

import psutil
import vici
from common import STATE, EXPORTS, PROTOCOLS, active, add_counter, database, event, get, initialize, now, put, validate_ports

CONFIG=Path('/etc/separ')
XRAY=Path('/usr/local/etc/xray/config.json')
CCD=Path('/etc/openvpn/ccd')
EVENTS=queue.Queue(maxsize=5000)
BOOT=Path('/proc/sys/kernel/random/boot_id').read_text().strip()

def command(args,timeout=30):
    r=subprocess.run(args,text=True,capture_output=True,timeout=timeout)
    if r.returncode: raise RuntimeError(f'{Path(args[0]).name}: {r.stderr[-500:] or r.stdout[-500:]}')
    return r.stdout

def atomic(path,text,mode=0o600):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    tmp=path.with_suffix(path.suffix+'.new')
    tmp.write_text(text); tmp.chmod(mode); os.replace(tmp,path)

def decode(value):
    if isinstance(value,bytes): return value.decode()
    if isinstance(value,dict): return {decode(k):decode(v) for k,v in value.items()}
    if isinstance(value,list): return [decode(v) for v in value]
    return value

def management(cmd):
    with socket.socket(socket.AF_UNIX) as s:
        s.settimeout(2); s.connect('/run/openvpn-server/amazon-mgmt.sock')
        s.recv(4096); s.sendall((cmd+'\n').encode())
        chunks=[]
        while True:
            try: chunk=s.recv(65536)
            except socket.timeout: break
            if not chunk: break
            chunks.append(chunk)
            if b'\nEND' in chunk or b'SUCCESS:' in chunk or b'ERROR:' in chunk: break
        return b''.join(chunks).decode(errors='replace')

def valid_user(u):
    uuid.UUID(u['uuid'])
    if not re.fullmatch(r'(u[a-f0-9]{32}|navid-test)',u['cn']): raise ValueError('invalid CN')
    if not re.fullmatch('[a-f0-9]{32}',u['id']): raise ValueError('invalid user ID')
    if not re.fullmatch('[A-Za-z0-9_-]{16,128}',u['password']): raise ValueError('invalid password')
    if not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,49}',u['name']): raise ValueError('invalid username')
    if any(p not in PROTOCOLS for p in json.loads(u['protocols'])): raise ValueError('invalid protocol')

def export_user(u,settings):
    valid_user(u)
    folder=EXPORTS/u['id']; folder.mkdir(mode=0o750,exist_ok=True)
    # State directory has setgid so generated exports remain readable by web service.
    folder.chmod(0o2750)
    protocols=json.loads(u['protocols'])
    ip=settings['server_ip']; ports=settings['ports']
    if 'reality' in protocols:
        r=settings['reality']
        uri=f'vless://{u["uuid"]}@{ip}:{ports["reality"]}?encryption=none&security=reality&sni={r["sni"]}&fp=chrome&pbk={r["public"]}&sid={r["sid"]}&type=tcp&flow=xtls-rprx-vision#SirGSM-{u["name"]}-REALITY\n'
        atomic(folder/'reality.txt',uri,0o640)
    if 'openvpn' in protocols:
        pki=Path('/etc/openvpn/easy-rsa/pki')
        if not (pki/'issued'/f'{u["cn"]}.crt').is_file():
            env=dict(os.environ,EASYRSA_BATCH='1',EASYRSA_ALGO='ec',EASYRSA_CURVE='prime256v1')
            subprocess.run(['flock','/run/sirgsm-pki.lock','./easyrsa','build-client-full',u['cn'],'nopass'],cwd='/etc/openvpn/easy-rsa',env=env,check=True,capture_output=True,timeout=30)
        text=Path('/etc/separ/openvpn-client-template').read_text()
        for tag,path in [('ca',pki/'ca.crt'),('cert',pki/'issued'/f'{u["cn"]}.crt'),('key',pki/'private'/f'{u["cn"]}.key'),('tls-crypt',Path('/etc/openvpn/server/tls-crypt.key'))]:
            data=path.read_text()
            if tag=='cert': data=data[data.index('-----BEGIN CERTIFICATE-----'):]
            text+=f'\n<{tag}>\n{data.strip()}\n</{tag}>\n'
        atomic(folder/'openvpn.ovpn',text,0o640)
    if 'ikev2' in protocols:
        ca=(CONFIG/'ike-ca.pem').read_bytes()
        atomic(folder/'ca.cer',ca.decode(),0o640)
        text=f'SirGSM IKEv2\nServer: {ip}\nRemote ID: {ip}\nUsername: {u["cn"]}\nPassword: {u["password"]}\nAuthentication: EAP-MSCHAPv2\nInstall the included ca.cer as a trusted VPN certificate before connecting.\nUDP 500 and 4500 must be reachable.\n\nفارسی: گواهی ca.cer را به عنوان گواهی مورد اعتماد VPN نصب کنید و سپس با نام کاربری و رمز بالا وصل شوید.\n'
        atomic(folder/'ikev2.txt',text,0o640)
        ca_uuid=str(uuid.uuid4())
        profile={'PayloadType':'Configuration','PayloadVersion':1,'PayloadIdentifier':f'net.separ.{u["id"]}',
                 'PayloadUUID':str(uuid.uuid4()),'PayloadDisplayName':f'SirGSM — {u["name"]}',
                 'PayloadContent':[
                   {'PayloadType':'com.apple.security.root','PayloadVersion':1,'PayloadIdentifier':f'net.separ.ca.{u["id"]}',
                    'PayloadUUID':ca_uuid,'PayloadDisplayName':'SirGSM IKEv2 CA','PayloadContent':__import__('ssl').PEM_cert_to_DER_cert(ca.decode())},
                   {'PayloadType':'com.apple.vpn.managed','PayloadVersion':1,'PayloadIdentifier':f'net.separ.vpn.{u["id"]}',
                    'PayloadUUID':str(uuid.uuid4()),'PayloadDisplayName':f'SirGSM {u["name"]}','UserDefinedName':f'SirGSM {u["name"]}',
                    'VPNType':'IKEv2','IKEv2':{'RemoteAddress':ip,'RemoteIdentifier':ip,
                    'AuthenticationMethod':'None','ExtendedAuthEnabled':1,'AuthName':u['cn'],'AuthPassword':u['password'],
                    'DeadPeerDetectionRate':'Medium','DisableMOBIKE':0,'EnablePFS':0},'IPv4':{'OverridePrimary':1}}]}
        atomic(folder/'ios.mobileconfig',plistlib.dumps(profile).decode(),0o640)
    if 'shadowsocks' in protocols:
        sskey=base64.b64encode(hashlib.sha256(u['password'].encode()).digest()).decode()
        auth=base64.urlsafe_b64encode(('2022-blake3-aes-256-gcm:'+settings['ss_master']+':'+sskey).encode()).decode().rstrip('=')
        atomic(folder/'shadowsocks.txt',f'ss://{auth}@{ip}:{ports["shadowsocks"]}#SirGSM-{u["name"]}\n',0o640)
    if 'trojan' in protocols:
        atomic(folder/'trojan.txt',f'trojan://{u["password"]}@{ip}:{ports["trojan"]}?security=tls&type=tcp&sni={ip}#SirGSM-{u["name"]}\n',0o640)
    if 'vmess' in protocols:
        data={'v':'2','ps':f'SirGSM-{u["name"]}','add':ip,'port':str(ports['vmess']),'id':u['uuid'],'aid':'0','scy':'auto','net':'ws','type':'none','host':ip,'path':'/sirgsm-vmess','tls':'tls','sni':ip}
        atomic(folder/'vmess.txt','vmess://'+base64.b64encode(json.dumps(data).encode()).decode()+'\n',0o640)

def collect_openvpn(db,users):
    bycn={u['cn']:u for u in users}
    # Final disconnect byte counts avoid losing traffic between status polls.
    spool=Path('/var/lib/separ-openvpn/events.jsonl')
    if spool.exists():
        fd=os.open(spool,os.O_RDWR|os.O_NOFOLLOW|os.O_CLOEXEC)
        with os.fdopen(fd,'r+') as f:
            info=os.fstat(f.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_uid!=0 or info.st_nlink!=1:
                raise RuntimeError('Unsafe OpenVPN accounting spool')
            fcntl.flock(f,fcntl.LOCK_EX)
            if os.fstat(f.fileno()).st_size>4*1024*1024:
                f.truncate(0)
                raise RuntimeError('OpenVPN spool exceeded safe size; accounting interrupted')
            lines=f.readlines(); f.seek(0); f.truncate()
        for line in lines:
            item=json.loads(line)
            u=bycn.get(item.get('cn'))
            if not u: continue
            key=f'ovpn:{item["cn"]}:{item["remote"]}'
            if item['kind']=='connect': db.execute('DELETE FROM counters WHERE key=?',(key,))
            else: add_counter(db,key,u['id'],'openvpn',int(item['in'])+int(item['out']))
    headers=[]; connected=[]
    for line in management('status 3').splitlines():
        fields=line.rstrip().split('\t')
        if fields[:2]==['HEADER','CLIENT_LIST']: headers=fields[2:]
        if fields[0]!='CLIENT_LIST': continue
        row=dict(zip(headers,fields[1:]))
        cn=row.get('Common Name'); u=bycn.get(cn)
        if not u: continue
        add_counter(db,f'ovpn:{cn}:{row["Real Address"]}',u['id'],'openvpn',int(row['Bytes Received'])+int(row['Bytes Sent']))
        connected.append(u['id'])
    return connected

def collect_xray(db,users):
    raw=command(['/usr/local/bin/xray','api','statsquery','--server=127.0.0.1:10085','-pattern','user>>>'],timeout=5)
    data=json.loads(raw); bycn={u['cn']:u for u in users}
    pid=command(['systemctl','show','xray','--property=MainPID','--value']).strip()
    for stat in data.get('stat',[]):
        parts=stat['name'].split('>>>')
        if len(parts)!=4: continue
        identity=parts[1].split('@',1)
        cn=identity[0]; protocol=identity[1] if len(identity)>1 else 'reality'
        if cn not in bycn or protocol not in ('reality','shadowsocks','trojan','vmess'): continue
        u=bycn[cn]
        add_counter(db,f'xray:{BOOT}:{pid}:{stat["name"]}',u['id'],protocol,int(stat.get('value',0)))

def ike_events():
    while True:
        try:
            for kind,data in vici.Session().listen(['child-updown'],timeout=5):
                if kind:
                    EVENTS.put(decode(data),timeout=2)
        except Exception:
            time.sleep(5)

def collect_ike(db,users):
    bycn={u['cn']:u for u in users}
    pid=command(['systemctl','show','strongswan','--property=MainPID','--value']).strip()
    packets=[decode(item) for item in vici.Session().list_sas()]
    while True:
        try: packets.append(EVENTS.get_nowait())
        except queue.Empty: break
    online=[]; sas=[]
    for packet in packets:
        for name,sa in packet.items():
            if not isinstance(sa,dict): continue
            u=bycn.get(sa.get('remote-eap-id',sa.get('remote-id')))
            if not u: continue
            if sa.get('state')=='ESTABLISHED': online.append(u['id'])
            sas.append((u['id'],sa['uniqueid']))
            for child in sa.get('child-sas',{}).values():
                total=int(child.get('bytes-in',0))+int(child.get('bytes-out',0))
                key=f'ike:{BOOT}:{pid}:{sa["uniqueid"]}:{child.get("uniqueid",child.get("spi-in",""))}'
                add_counter(db,key,u['id'],'ikev2',total)
    return online,sas

def apply(users,settings):
    enabled=[u for u in users if active(u)]
    base=json.loads((CONFIG/'xray-base.json').read_text())
    for inbound in base['inbounds']:
        if inbound['protocol']=='vless':
            inbound['settings']['clients']=[{'id':u['uuid'],'flow':'xtls-rprx-vision','email':u['cn'],'level':0} for u in enabled if 'reality' in json.loads(u['protocols'])]
        elif inbound['protocol'] in ('trojan','vmess','shadowsocks'):
            protocol=inbound['protocol']
            clients=[]
            for u in enabled:
                if protocol not in json.loads(u['protocols']): continue
                c={'email':u['cn']+'@'+protocol,'level':0}
                if protocol=='vmess': c.update(id=u['uuid'],alterId=0)
                else: c['password']=u['password']
                if protocol=='shadowsocks': c['password']=base64.b64encode(hashlib.sha256(u['password'].encode()).digest()).decode()
                clients.append(c)
            inbound['settings']['users' if protocol=='shadowsocks' else 'clients']=clients
            if protocol=='shadowsocks' and not clients:
                # Preserve multi-user mode when the last account expires. Single-user
                # SS2022 would otherwise accept the shared server key on its own.
                inbound['settings']['users']=[{'password':base64.b64encode(os.urandom(32)).decode(),'email':'disabled@shadowsocks','level':0}]
    atomic('/run/separ-xray-test.json',json.dumps(base),0o640)
    command(['/usr/local/bin/xray','run','-test','-config','/run/separ-xray-test.json'])
    # The worker samples counters before applying. A full core restart also ends disabled sessions.
    atomic(XRAY,json.dumps(base,indent=2),0o640); shutil.chown(XRAY,group='xray')
    command(['systemctl','restart','xray'])
    CCD.mkdir(exist_ok=True)
    wanted={u['cn'] for u in enabled if 'openvpn' in json.loads(u['protocols'])}
    for p in CCD.iterdir():
        if p.name not in wanted and p.is_file(): p.unlink()
    for cn in wanted: atomic(CCD/cn,'# Managed by Separ\n',0o644)
    # EAP secrets are replaced, rather than accumulated, so expired accounts cannot reconnect.
    parts=['secrets {']
    for u in enabled:
        if 'ikev2' in json.loads(u['protocols']):
            parts.append(f'eap-{u["id"]} {{ id = {u["cn"]}\nsecret = "{u["password"]}"\n}}')
    parts.append('}')
    atomic('/etc/swanctl/conf.d/separ-users.conf','\n'.join(parts))
    command(['swanctl','--load-creds','--clear'])
    for u in users:
        if u['cn'] not in wanted:
            try: management('kill '+u['cn'])
            except OSError: pass
    session=vici.Session()
    for packet in session.list_sas():
        for sa in decode(packet).values():
            match=next((u for u in enabled if u['cn']==sa.get('remote-eap-id') and 'ikev2' in json.loads(u['protocols'])),None)
            if not match:
                list(vici.Session().terminate({'ike-id':sa['uniqueid'],'timeout':'1000'}))

def tick():
    errors=[]; online=[]
    with database() as db:
        settings={'reality':get(db,'reality'),'server_ip':get(db,'server_ip'),'ports':validate_ports(get(db,'ports')),'ss_master':get(db,'ss_master')}
        users=[dict(u) for u in db.execute('SELECT * FROM users')]
        for u in users: valid_user(u)
        for key,fn in [('reality',lambda:collect_xray(db,users)),('openvpn',lambda:collect_openvpn(db,users)),('ikev2',lambda:collect_ike(db,users))]:
            try:
                value=fn()
                if key=='openvpn': online.extend(value)
                if key=='ikev2': online.extend(value[0])
                put(db,'health',key+'_accounting','ok')
            except Exception as e:
                errors.append(key+': '+str(e)[:240]); put(db,'health',key+'_accounting','error')
        users=[dict(u) for u in db.execute('SELECT * FROM users')]
        for u in users:
            if not u['provisioned'] and not u['deleted']:
                try:
                    export_user(u,settings)
                    db.execute('UPDATE users SET provisioned=1 WHERE id=?',(u['id'],))
                except Exception as e: errors.append('provision: '+str(e)[:240])
        # Fail closed for accounts with finite quotas if a protocol's meter is unavailable.
        metering_ok=not errors
        effective=[]
        for u in users:
            u=dict(u)
            if u['quota'] and not metering_ok: u['enabled']=0
            effective.append(u)
        signature=hashlib.sha256(json.dumps([(u['id'],active(u),u['protocols']) for u in effective]).encode()).hexdigest()
        previous=get(db,'applied_signature')
        if signature!=previous:
            try:
                apply(effective,settings)
                put(db,'settings','applied_signature',signature)
                event(db,'sync','دسترسی سرویس‌ها با حساب‌های پنل همگام شد')
            except Exception as e: errors.append('apply: '+str(e)[:300])
        vm=psutil.virtual_memory()
        put(db,'health','system',{'memory_percent':vm.percent,'cpu_percent':psutil.cpu_percent(),'disk_percent':psutil.disk_usage('/').percent,'uptime':int(time.time()-psutil.boot_time())})
        put(db,'health','services',{name:subprocess.run(['systemctl','is-active',unit],capture_output=True,text=True).stdout.strip()=='active' for name,unit in [('reality','xray'),('openvpn','openvpn-server@amazon'),('ikev2','strongswan'),('shadowsocks','xray'),('trojan','xray'),('vmess','xray'),('telegram','sirgsm-mtg')]})
        put(db,'health','online_vpn_users',list(set(online)))
        put(db,'health','errors',errors)
        put(db,'health','last_poll',now())

if __name__=='__main__':
    os.umask(0o007)
    initialize()
    threading.Thread(target=ike_events,daemon=True).start()
    while True:
        try: tick()
        except Exception as e:
            print(f'Worker error: {type(e).__name__}: {e}',flush=True)
            with database() as db: put(db,'health','errors',[str(e)[:300]])
        time.sleep(5)
