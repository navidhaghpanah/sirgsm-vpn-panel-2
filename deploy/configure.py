#!/usr/bin/env python3
"""One-server installer/configurator. State and secrets never live in the repo."""
import argparse
import base64
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import subprocess
import sys
import time
import uuid
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
from common import STATE,EXPORTS,PROTOCOLS,database,event,get,hash_password,initialize,now,put,validate_ports

ROOT=Path('/opt/separ')
CFG=Path('/etc/separ')

def validate_domain(value,ip,resolve=True):
    value=value.lower().rstrip('.')
    if len(value)>253 or '.' not in value or not all(re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',p) for p in value.split('.')):
        raise ValueError('Invalid DNS domain; use an ASCII hostname, without https:// or a port')
    try:
        ipaddress.ip_address(value)
    except ValueError:
        pass
    else:
        raise ValueError('Use --server-ip for an IP address')
    if resolve:
        addresses={item[4][0] for item in socket.getaddrinfo(value,80,type=socket.SOCK_STREAM)}
        if addresses!={ip}:
            raise ValueError('Domain must resolve only to the server IPv4; remove proxying and unrelated A/AAAA records')
    return value

def panel_domain(domain,ip,acme):
    domain=validate_domain(domain,ip)
    write('/etc/nginx/sites-available/sirgsm-domain',f'''server {{
 listen 80;
 server_name {domain};
 location /.well-known/acme-challenge/ {{ root {acme}; }}
 location / {{ return 404; }}
}}
''',0o644)
    enabled=Path('/etc/nginx/sites-enabled/sirgsm-domain')
    if not enabled.exists():enabled.symlink_to('/etc/nginx/sites-available/sirgsm-domain')
    run('nginx','-t');run('systemctl','reload','nginx')
    run('/opt/sirgsm-certbot/bin/certbot','certonly','--webroot','-w',str(acme),'-d',domain,'--cert-name','sirgsm-domain','--non-interactive','--agree-tos','--register-unsafely-without-email')
    panel=Path('/etc/nginx/sites-available/separ-panel').read_text()
    panel=panel.replace(' include /etc/nginx/snippets/sirgsm-canonical.conf;\n','')
    panel=panel.replace(f'server_name {ip};',f'server_name {domain};').replace('/live/sirgsm-ip/','/live/sirgsm-domain/')
    current=Path('/etc/nginx/sites-available/sirgsm-domain').read_text()
    write('/etc/nginx/sites-available/sirgsm-domain',current+panel,0o644)
    run('nginx','-t');run('systemctl','reload','nginx')
    write('/etc/letsencrypt/renewal-hooks/deploy/sirgsm-domain','#!/bin/sh\n[ "$RENEWED_LINEAGE" != /etc/letsencrypt/live/sirgsm-domain ] || systemctl reload nginx\n',0o700)
    write(CFG/'panel-domain',domain+'\n')
    write('/etc/nginx/snippets/sirgsm-canonical.conf',f'location = / {{ return 302 https://{domain}:8443/; }}\n',0o644)
    ip_site=Path('/etc/nginx/sites-available/separ-panel')
    text=ip_site.read_text()
    if 'include /etc/nginx/snippets/sirgsm-canonical.conf;' not in text:
        write(ip_site,text.replace(' client_max_body_size',' include /etc/nginx/snippets/sirgsm-canonical.conf;\n client_max_body_size'),0o644)
    run('nginx','-t');run('systemctl','reload','nginx')
    with database() as db:put(db,'settings','public_origin',f'https://{domain}:8443')

def run(*args,**kwargs):
    result=subprocess.run(args,text=True,capture_output=True,check=True,**kwargs)
    return result.stdout

def write(path,text,mode=0o600,group=None):
    path=Path(path); path.parent.mkdir(parents=True,exist_ok=True)
    path.write_text(text);path.chmod(mode)
    if group: shutil.chown(path,group=group)

def configure_tcp_congestion(mode='auto'):
    """Persist BBR only after the running kernel accepts it; never restart tunnels."""
    if mode not in ('auto','bbr','keep'):raise ValueError('Invalid TCP congestion mode')
    if mode=='keep':return None
    try:
        run('modprobe','tcp_bbr')
    except (OSError,subprocess.CalledProcessError):
        pass  # A built-in BBR implementation does not need a loadable module.
    try:
        available=run('sysctl','-n','net.ipv4.tcp_available_congestion_control').split()
        if 'bbr' not in available:raise RuntimeError('The running kernel does not provide BBR')
        run('sysctl','-w','net.ipv4.tcp_congestion_control=bbr')
        if run('sysctl','-n','net.ipv4.tcp_congestion_control').strip()!='bbr':
            raise RuntimeError('The running kernel did not activate BBR')
    except (OSError,subprocess.CalledProcessError,RuntimeError) as error:
        if mode=='bbr':raise RuntimeError('BBR could not be enabled') from error
        print('BBR unavailable; keeping the current TCP congestion setting.')
        return None
    write('/etc/modules-load.d/sirgsm-bbr.conf','tcp_bbr\n',0o644)
    write('/etc/sysctl.d/99-sirgsm-tcp.conf',
          '# SirGSM: TCP congestion control for new server TCP connections.\nnet.ipv4.tcp_congestion_control=bbr\n',0o644)
    print('TCP congestion control: BBR (persistent; affects new TCP connections).')
    return 'bbr'

def pki():
    if subprocess.run(['id','sirgsm-openvpn'],capture_output=True).returncode:
        run('useradd','--system','--home','/nonexistent','--shell','/usr/sbin/nologin','sirgsm-openvpn')
    if not Path('/etc/openvpn/easy-rsa/pki/ca.crt').exists():
        shutil.copytree('/usr/share/easy-rsa','/etc/openvpn/easy-rsa',dirs_exist_ok=True)
        env=dict(os.environ,EASYRSA_BATCH='1',EASYRSA_ALGO='ec',EASYRSA_CURVE='prime256v1')
        cwd='/etc/openvpn/easy-rsa'
        for args in [('init-pki',),('build-ca','nopass'),('build-server-full','amazon-server','nopass')]:
            run('./easyrsa',*args,cwd=cwd,env=env)
    run('./easyrsa','gen-crl',cwd='/etc/openvpn/easy-rsa',env=dict(os.environ,EASYRSA_BATCH='1'))
    base=Path('/etc/openvpn/easy-rsa/pki'); dest=Path('/etc/openvpn/server');dest.mkdir(exist_ok=True);dest.chmod(0o755)
    for src,name in [('ca.crt','ca.crt'),('issued/amazon-server.crt','amazon-server.crt'),('private/amazon-server.key','amazon-server.key'),('crl.pem','crl.pem')]:
        shutil.copyfile(base/src,dest/name)
        (dest/name).chmod(0o644 if name=='crl.pem' else 0o600)
    if not (dest/'tls-crypt.key').exists():run('openvpn','--genkey','tls-crypt',str(dest/'tls-crypt.key'))

def ike_pki(ip):
    for folder in ['private','x509','x509ca','conf.d']: Path('/etc/swanctl',folder).mkdir(exist_ok=True)
    if not (CFG/'ike-ca.key').exists():
        run('openssl','genrsa','-out',str(CFG/'ike-ca.key'),'3072')
        run('openssl','req','-x509','-new','-sha256','-days','3650','-key',str(CFG/'ike-ca.key'),'-out',str(CFG/'ike-ca.pem'),'-subj','/CN=SirGSM IKEv2 VPN CA','-addext','basicConstraints=critical,CA:TRUE','-addext','keyUsage=critical,keyCertSign,cRLSign')
    # The private VPN certificate has a separate lifecycle from the public IP certificate.
    if not Path('/etc/swanctl/private/separ.key').exists():run('openssl','genrsa','-out','/etc/swanctl/private/separ.key','3072')
    run('openssl','req','-new','-key','/etc/swanctl/private/separ.key','-out',str(CFG/'ike-server.csr'),'-subj',f'/CN={ip}')
    write(CFG/'ike-server.ext',f'basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth,1.3.6.1.5.5.8.2.2\nsubjectAltName=IP:{ip}\n')
    run('openssl','x509','-req','-in',str(CFG/'ike-server.csr'),'-CA',str(CFG/'ike-ca.pem'),'-CAkey',str(CFG/'ike-ca.key'),'-CAcreateserial','-out','/etc/swanctl/x509/separ.pem','-days','825','-sha256','-extfile',str(CFG/'ike-server.ext'))
    shutil.copyfile(CFG/'ike-ca.pem','/etc/swanctl/x509ca/separ-ca.pem')

def network(iface):
    write('/etc/sysctl.d/90-openvpn-amazon.conf','net.ipv4.ip_forward=1\nnet.ipv6.conf.all.forwarding=1\n')
    run('sysctl','-p','/etc/sysctl.d/90-openvpn-amazon.conf')
    script='''#!/bin/sh
set -eu
exec 9>/run/sirgsm-network.lock
flock 9
iptables -N SIRGSM_VPN_GUARD 2>/dev/null || true
iptables -F SIRGSM_VPN_GUARD
for destination in 0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16 172.16.0.0/12 192.168.0.0/16 198.18.0.0/15 224.0.0.0/4 240.0.0.0/4; do
 iptables -A SIRGSM_VPN_GUARD -d "$destination" -j REJECT
 iptables -C OUTPUT -m owner --uid-owner xray -m conntrack --ctstate NEW -d "$destination" -j REJECT 2>/dev/null || iptables -I OUTPUT -m owner --uid-owner xray -m conntrack --ctstate NEW -d "$destination" -j REJECT
done
for transport in udp tcp; do
 iptables -D OUTPUT -m owner --uid-owner xray -d 127.0.0.53/32 -p "$transport" --dport 53 -j ACCEPT 2>/dev/null || true
 iptables -I OUTPUT -m owner --uid-owner xray -d 127.0.0.53/32 -p "$transport" --dport 53 -j ACCEPT
done
iptables -A SIRGSM_VPN_GUARD -j RETURN
for source in 10.83.0.0/24 10.85.0.0/24; do
 iptables -C FORWARD -s "$source" -j SIRGSM_VPN_GUARD 2>/dev/null || iptables -I FORWARD -s "$source" -j SIRGSM_VPN_GUARD
 iptables -C INPUT -s "$source" -j DROP 2>/dev/null || iptables -I INPUT -s "$source" -j DROP
done
iptables -t nat -C POSTROUTING -s 10.83.0.0/24 -o @IFACE@ -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.83.0.0/24 -o @IFACE@ -j MASQUERADE
iptables -t nat -C POSTROUTING -s 10.85.0.0/24 -o @IFACE@ -m policy --dir out --pol none -j MASQUERADE 2>/dev/null || iptables -t nat -A POSTROUTING -s 10.85.0.0/24 -o @IFACE@ -m policy --dir out --pol none -j MASQUERADE
iptables -C FORWARD -i tun-amazon -o @IFACE@ -s 10.83.0.0/24 -j ACCEPT 2>/dev/null || iptables -A FORWARD -i tun-amazon -o @IFACE@ -s 10.83.0.0/24 -j ACCEPT
iptables -C FORWARD -s 10.85.0.0/24 -m policy --dir in --pol ipsec -j ACCEPT 2>/dev/null || iptables -A FORWARD -s 10.85.0.0/24 -m policy --dir in --pol ipsec -j ACCEPT
iptables -C FORWARD -d 10.83.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.83.0.0/24 -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
iptables -C FORWARD -d 10.85.0.0/24 -m policy --dir out --pol ipsec -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT 2>/dev/null || iptables -A FORWARD -d 10.85.0.0/24 -m policy --dir out --pol ipsec -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT
for source in fd85:1::/112 fd83:2::/64; do
 ip6tables -C FORWARD -s "$source" -j REJECT 2>/dev/null || ip6tables -I FORWARD -s "$source" -j REJECT
 ip6tables -C INPUT -s "$source" -j DROP 2>/dev/null || ip6tables -I INPUT -s "$source" -j DROP
done
for destination in ::1/128 fc00::/7 fe80::/10; do
 ip6tables -C OUTPUT -m owner --uid-owner xray -m conntrack --ctstate NEW -d "$destination" -j REJECT 2>/dev/null || ip6tables -I OUTPUT -m owner --uid-owner xray -m conntrack --ctstate NEW -d "$destination" -j REJECT
done
'''.replace('@IFACE@',iface)
    write('/usr/local/sbin/openvpn-amazon-network',script,0o700)
    write('/usr/local/sbin/separ-ike-network',script,0o700)
    run('/usr/local/sbin/openvpn-amazon-network')

def services():
    write('/etc/systemd/system/separ-worker.service','''[Unit]
Description=SirGSM VPN Panel 2 - accounting and enforcement
After=network-online.target xray.service openvpn-server@amazon.service strongswan.service
Wants=xray.service openvpn-server@amazon.service strongswan.service
[Service]
Type=simple
Group=separ
WorkingDirectory=/opt/separ/backend
ExecStart=/opt/sirgsm-runtime/bin/python -u worker.py
Restart=always
RestartSec=2
UMask=0007
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=/etc/separ /etc/swanctl /etc/openvpn /usr/local/etc/xray /var/lib/separ /var/lib/separ-exports /var/lib/separ-openvpn
[Install]
WantedBy=multi-user.target
''',0o644)
    write('/etc/systemd/system/separ-web.service','''[Unit]
Description=SirGSM VPN Panel 2 - private administration
After=network.target
[Service]
User=separ
Group=separ
WorkingDirectory=/opt/separ/backend
ExecStart=/opt/sirgsm-runtime/bin/python -m uvicorn app:app --host 127.0.0.1 --port 8099 --proxy-headers --forwarded-allow-ips 127.0.0.1 --no-access-log
Restart=always
RestartSec=2
UMask=0007
NoNewPrivileges=yes
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
ReadWritePaths=/var/lib/separ
[Install]
WantedBy=multi-user.target
''',0o644)
    write('/etc/systemd/system/openvpn-server@amazon.service.d/network.conf','[Service]\nExecStartPre=+/usr/local/sbin/openvpn-amazon-network\n',0o644)
    write('/etc/systemd/system/strongswan.service.d/separ.conf','[Service]\nExecStartPre=/usr/local/sbin/separ-ike-network\n',0o644)
    write('/etc/systemd/system/sirgsm-cert-renew.service','''[Unit]
Description=Renew SirGSM public IP and optional domain TLS certificates
[Service]
Type=oneshot
ExecStart=/opt/sirgsm-certbot/bin/certbot renew --quiet --no-random-sleep-on-renew
''',0o644)
    write('/etc/systemd/system/sirgsm-cert-renew.timer','''[Unit]
Description=Check six-day IP certificate twice daily
[Timer]
OnCalendar=*-*-* 00,12:00:00
RandomizedDelaySec=1800
Persistent=true
[Install]
WantedBy=timers.target
''',0o644)
    # OpenVPN CRLs have a short validity and must also renew unattended.
    write('/usr/local/sbin/sirgsm-renew-crl','''#!/bin/sh
set -eu
exec 9>/run/sirgsm-pki.lock
flock 9
cd /etc/openvpn/easy-rsa
EASYRSA_BATCH=1 ./easyrsa gen-crl
install -m 644 pki/crl.pem /etc/openvpn/server/crl.pem
''',0o700)
    write('/etc/systemd/system/sirgsm-crl.service','[Service]\nType=oneshot\nExecStart=/usr/local/sbin/sirgsm-renew-crl\n',0o644)
    write('/etc/systemd/system/sirgsm-crl.timer','[Timer]\nOnCalendar=weekly\nPersistent=true\n[Install]\nWantedBy=timers.target\n',0o644)
    write('/usr/local/sbin/sirgsm-renew-ike','''#!/bin/sh
set -eu
openssl x509 -checkend 2592000 -noout -in /etc/swanctl/x509/separ.pem && exit 0
umask 077
openssl x509 -req -in /etc/separ/ike-server.csr -CA /etc/separ/ike-ca.pem -CAkey /etc/separ/ike-ca.key -CAcreateserial -out /etc/swanctl/x509/separ.pem.new -days 825 -sha256 -extfile /etc/separ/ike-server.ext
mv /etc/swanctl/x509/separ.pem.new /etc/swanctl/x509/separ.pem
swanctl --load-creds --clear
''',0o700)
    write('/etc/systemd/system/sirgsm-ike-cert.service','[Service]\nType=oneshot\nExecStart=/usr/local/sbin/sirgsm-renew-ike\n',0o644)
    write('/etc/systemd/system/sirgsm-ike-cert.timer','[Timer]\nOnCalendar=weekly\nPersistent=true\n[Install]\nWantedBy=timers.target\n',0o644)

def telegram(ip):
    if not Path('/usr/local/bin/mtg').is_file():
        raise RuntimeError('mtg must be installed before configuring Telegram')
    if subprocess.run(['id','sirgsm-mtg'],capture_output=True).returncode:
        run('useradd','--system','--home','/nonexistent','--shell','/usr/sbin/nologin','sirgsm-mtg')
    folder=Path('/etc/sirgsm-mtg');folder.mkdir(exist_ok=True);folder.chmod(0o750);shutil.chown(folder,group='sirgsm-mtg')
    with database() as db:
        info=get(db,'telegram')
        secret=info['secret'] if info else 'ee'+secrets.token_hex(16)+'www.microsoft.com'.encode().hex()
        # DNS is an address convenience, not a way to conceal the public server IP.
        host=ip.replace('.','-')+'.sslip.io'
        put(db,'settings','telegram',{'secret':secret,'port':2096,'host':host,'direct':ip,
              'url':f'https://t.me/proxy?server={host}&port=2096&secret={secret}',
              'direct_url':f'https://t.me/proxy?server={ip}&port=2096&secret={secret}'})
    write(folder/'config.toml',f'''secret = "{secret}"
bind-to = "0.0.0.0:2096"
prefer-ip = "only-ipv4"
public-ipv4 = "{ip}"
concurrency = 1024
[stats.prometheus]
enabled = true
bind-to = "127.0.0.1:3129"
''',0o640,group='sirgsm-mtg')
    write('/etc/systemd/system/sirgsm-mtg.service','''[Unit]
Description=SirGSM public Telegram MTProto proxy (independent quota)
After=network-online.target
[Service]
User=sirgsm-mtg
Group=sirgsm-mtg
ExecStart=/usr/local/bin/mtg run /etc/sirgsm-mtg/config.toml
Restart=always
RestartSec=3
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
PrivateTmp=true
PrivateDevices=true
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
''',0o644)

def main():
    configured_at=now()
    parser=argparse.ArgumentParser()
    parser.add_argument('--server-ip',required=True)
    parser.add_argument('--domain')
    parser.add_argument('--openvpn-transport',choices=['tcp','udp'])
    parser.add_argument('--tcp-congestion',choices=['auto','bbr','keep'],default='auto')
    args=parser.parse_args();ip=str(ipaddress.IPv4Address(args.server_ip))
    if not ipaddress.ip_address(ip).is_global:raise ValueError('A public IPv4 address is required')
    if os.geteuid()!=0:raise PermissionError('Run as root')
    domain=args.domain or ((CFG/'panel-domain').read_text().strip() if (CFG/'panel-domain').exists() else '')
    if domain:domain=validate_domain(domain,ip)
    transport=args.openvpn_transport or ((CFG/'openvpn-transport').read_text().strip() if (CFG/'openvpn-transport').exists() else 'tcp')
    if transport not in ('tcp','udp'):raise ValueError('Invalid OpenVPN transport')
    os.umask(0o027)
    iface=run('ip','-4','route','show','default').split(' dev ')[1].split()[0]
    if not re.fullmatch('[A-Za-z0-9_.:-]{1,15}',iface):raise ValueError('Invalid network interface')
    if subprocess.run(['id','separ'],capture_output=True).returncode:run('useradd','--system','--home','/var/lib/separ','--shell','/usr/sbin/nologin','separ')
    CFG.mkdir(mode=0o700,exist_ok=True);CFG.chmod(0o700)
    write(CFG/'openvpn-transport',transport+'\n')
    for p in [STATE,EXPORTS]:p.mkdir(exist_ok=True);shutil.chown(p,group='separ');p.chmod(0o2770 if p==STATE else 0o2750)
    # Upgrade legacy export layout, but never leave root-generated secrets web-writable.
    if (STATE/'exports').is_dir():
        for folder in (STATE/'exports').iterdir():
            if not (EXPORTS/folder.name).exists():shutil.move(str(folder),EXPORTS/folder.name)
        (STATE/'exports').rmdir()
    initialize()
    with database() as db:
        existing=get(db,'admin_hash') is not None
        put(db,'settings','server_ip',ip)
        ports=validate_ports(get(db,'ports',{'reality':443,'openvpn':2053,'ikev2':'500 / 4500','shadowsocks':8388,'trojan':2087,'vmess':2083}))
        put(db,'settings','ports',ports)
        master=get(db,'ss_master') or base64.b64encode(os.urandom(32)).decode()
        if not isinstance(master,str) or len(base64.b64decode(master,validate=True))!=32:
            raise ValueError('Invalid Shadowsocks server key in database')
        put(db,'settings','ss_master',master)
        if not existing:
            password=secrets.token_urlsafe(26)
            put(db,'settings','admin_user','admin');put(db,'settings','admin_hash',hash_password(password))
            write('/root/sirgsm-admin.txt',f'Panel: https://{ip}:8443\nUsername: admin\nPassword: {password}\n')
        # Preserve the active REALITY key pair and existing imported accounts on upgrades.
        if (CFG/'xray-base.json').exists():base=json.loads((CFG/'xray-base.json').read_text())
        else:
            keys=run('/usr/local/bin/xray','x25519').splitlines()
            private=keys[0].split(': ',1)[1];public=keys[1].split(': ',1)[1];sid=secrets.token_hex(8)
            put(db,'settings','reality',{'public':public,'sid':sid,'sni':'www.microsoft.com'})
            base={'log':{'loglevel':'warning'},'inbounds':[{'tag':'reality','listen':'0.0.0.0','port':ports['reality'],'protocol':'vless','settings':{'clients':[],'decryption':'none'},'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':False,'target':'www.microsoft.com:443','xver':0,'serverNames':['www.microsoft.com'],'privateKey':private,'shortIds':[sid]}}}],'outbounds':[{'protocol':'freedom','tag':'direct'},{'protocol':'blackhole','tag':'blocked'}]}
        base['inbounds']=[i for i in base['inbounds'] if i['protocol']=='vless']
        tls={'minVersion':'1.2','certificates':[{'certificateFile':'/usr/local/etc/xray/tls/fullchain.pem','keyFile':'/usr/local/etc/xray/tls/privkey.pem'}]}
        base['inbounds'] += [
         {'tag':'shadowsocks','listen':'0.0.0.0','port':ports['shadowsocks'],'protocol':'shadowsocks','settings':{'method':'2022-blake3-aes-256-gcm','password':master,'network':'tcp,udp','users':[]}},
         {'tag':'trojan','listen':'0.0.0.0','port':ports['trojan'],'protocol':'trojan','settings':{'clients':[]},'streamSettings':{'network':'tcp','security':'tls','tlsSettings':tls}},
         {'tag':'vmess','listen':'0.0.0.0','port':ports['vmess'],'protocol':'vmess','settings':{'clients':[]},'streamSettings':{'network':'ws','security':'tls','tlsSettings':tls,'wsSettings':{'path':'/sirgsm-vmess'}}}]
        base['api']={'tag':'api','listen':'127.0.0.1:10085','services':['StatsService','HandlerService']}
        base['stats']={};base['policy']={'levels':{'0':{'statsUserUplink':True,'statsUserDownlink':True}}}
        base['routing']={'domainStrategy':'IPOnDemand','rules':[{'type':'field','ip':['geoip:private','100.64.0.0/10','169.254.0.0/16'],'outboundTag':'blocked'}]}
        write(CFG/'xray-base.json',json.dumps(base,indent=2))
        put(db,'settings','applied_signature',None)
        db.execute('UPDATE users SET provisioned=0')
        event(db,'setup','SirGSM VPN Panel 2 configured')
    for p in STATE.iterdir():
        if p.is_file():shutil.chown(p,group='separ');p.chmod(0o660)
    for folder in EXPORTS.iterdir():
        if folder.is_dir():
            folder.chmod(0o2750);shutil.chown(folder,group='separ')
            for p in folder.iterdir():shutil.chown(p,group='separ');p.chmod(0o640)
    pki();ike_pki(ip)
    openvpn=f'''port {ports['openvpn']}
proto {'udp' if transport=='udp' else 'tcp-server'}
dev tun-amazon
topology subnet
server 10.83.0.0 255.255.255.0
server-ipv6 fd83:2::/64
ca /etc/openvpn/server/ca.crt
cert /etc/openvpn/server/amazon-server.crt
key /etc/openvpn/server/amazon-server.key
crl-verify /etc/openvpn/server/crl.pem
dh none
tls-crypt /etc/openvpn/server/tls-crypt.key
tls-version-min 1.2
remote-cert-tls client
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
allow-compression no
push "redirect-gateway def1 ipv6 bypass-dhcp"
push "block-ipv6"
push "dhcp-option DNS 1.1.1.1"
push "dhcp-option DNS 8.8.8.8"
{'tcp-nodelay' if transport=='tcp' else 'explicit-exit-notify 1'}
keepalive 10 120
persist-key
persist-tun
user sirgsm-openvpn
group sirgsm-openvpn
verb 3
status /run/openvpn-server/amazon-status.log
management /run/openvpn-server/amazon-mgmt.sock unix
client-config-dir /etc/openvpn/ccd
ccd-exclusive
script-security 2
client-connect /opt/separ/backend/openvpn_event.py
client-disconnect /opt/separ/backend/openvpn_event.py
# duplicate-cn deliberately omitted: one simultaneous connection per certificate.
'''
    write('/etc/openvpn/server/amazon.conf',openvpn)
    write(CFG/'openvpn-client-template',f'''client
dev tun
proto {'udp' if transport=='udp' else 'tcp-client'}
remote {ip} {ports['openvpn']}
setenv FRIENDLY_NAME SirGSM
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
verify-x509-name amazon-server name
auth-nocache
tls-version-min 1.2
data-ciphers AES-256-GCM:AES-128-GCM:CHACHA20-POLY1305
allow-compression no
verb 3
''')
    Path('/etc/openvpn/ccd').mkdir(exist_ok=True)
    Path('/etc/openvpn/ccd').chmod(0o755)
    spool=Path('/var/lib/separ-openvpn');spool.mkdir(exist_ok=True);shutil.chown(spool,user='root',group='sirgsm-openvpn');spool.chmod(0o750)
    log=spool/'events.jsonl'
    fd=os.open(log,os.O_WRONLY|os.O_CREAT|os.O_NOFOLLOW|os.O_CLOEXEC,0o660)
    import stat
    with os.fdopen(fd,'a') as f:
        info=os.fstat(f.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1:raise RuntimeError('Unsafe existing accounting file')
        os.fchown(f.fileno(),0,__import__('grp').getgrnam('sirgsm-openvpn').gr_gid);os.fchmod(f.fileno(),0o660)
    (ROOT/'backend/openvpn_event.py').chmod(0o755)
    swan='''connections {
 separ {
  version = 2
  local_addrs = %any
  pools = separ-v4,separ-v6
  proposals = aes256gcm16-prfsha384-ecp384,aes128gcm16-prfsha256-ecp256,aes256-sha256-modp2048,aes128-sha256-modp2048
  fragmentation = yes
  encap = yes
  dpd_delay = 30s
  reauth_time = 0
  unique = replace
  send_cert = always
  local { auth = pubkey
   certs = separ.pem
   id = @IP@
  }
  remote { auth = eap-mschapv2
   eap_id = %any
  }
  children { internet {
   local_ts = 0.0.0.0/0,::/0
   esp_proposals = aes256gcm16,aes128gcm16,aes256-sha256,aes128-sha256
   dpd_action = clear
   rekey_time = 1h
  } }
 }
}
pools {
 separ-v4 { addrs = 10.85.0.0/24
  dns = 1.1.1.1,8.8.8.8
 }
 separ-v6 { addrs = fd85:1::/112
 }
}
'''.replace('@IP@',ip)
    write('/etc/swanctl/conf.d/separ.conf',swan)
    network(iface);configure_tcp_congestion(args.tcp_congestion);services();telegram(ip)
    acme=Path('/var/www/separ-acme');acme.mkdir(exist_ok=True);acme.chmod(0o755)
    write('/etc/nginx/sites-available/separ-acme',f'''server {{
 listen 80;
 server_name {ip};
 location /.well-known/acme-challenge/ {{ root /var/www/separ-acme; }}
 location / {{ return 404; }}
}}
''',0o644)
    enabled=Path('/etc/nginx/sites-enabled/separ-acme')
    if not enabled.exists():enabled.symlink_to('/etc/nginx/sites-available/separ-acme')
    run('nginx','-t');run('systemctl','reload','nginx')
    run('/opt/sirgsm-certbot/bin/certbot','certonly','--webroot','-w',str(acme),'--ip-address',ip,'--preferred-profile','shortlived','--cert-name','sirgsm-ip','--non-interactive','--agree-tos','--register-unsafely-without-email')
    write('/usr/local/sbin/sirgsm-cert-deploy','''#!/bin/sh
set -eu
install -d -m 750 -o root -g xray /usr/local/etc/xray/tls
install -m 640 -o root -g xray /etc/letsencrypt/live/sirgsm-ip/fullchain.pem /usr/local/etc/xray/tls/fullchain.pem
install -m 640 -o root -g xray /etc/letsencrypt/live/sirgsm-ip/privkey.pem /usr/local/etc/xray/tls/privkey.pem
systemctl reload nginx
systemctl try-restart xray
''',0o700)
    write('/etc/letsencrypt/renewal-hooks/deploy/sirgsm-ip','#!/bin/sh\n[ "$RENEWED_LINEAGE" != /etc/letsencrypt/live/sirgsm-ip ] || /usr/local/sbin/sirgsm-cert-deploy\n',0o700)
    # Stage TLS files before the worker starts any TLS inbounds.
    Path('/usr/local/etc/xray/tls').mkdir(exist_ok=True)
    shutil.chown('/usr/local/etc/xray/tls',group='xray');Path('/usr/local/etc/xray/tls').chmod(0o750)
    for name in ['fullchain.pem','privkey.pem']:
        target=Path('/usr/local/etc/xray/tls')/name
        shutil.copyfile(Path('/etc/letsencrypt/live/sirgsm-ip')/name,target);target.chmod(0o640);shutil.chown(target,group='xray')
    write('/etc/nginx/sites-available/separ-panel',f'''server {{
 listen 8443 ssl;
 server_name {ip};
 ssl_certificate /etc/letsencrypt/live/sirgsm-ip/fullchain.pem;
 ssl_certificate_key /etc/letsencrypt/live/sirgsm-ip/privkey.pem;
 ssl_protocols TLSv1.2 TLSv1.3;
 server_tokens off;
 access_log off;
 client_max_body_size 32k;
 location / {{
  proxy_pass http://127.0.0.1:8099;
  proxy_set_header Host $http_host;
  proxy_set_header X-Forwarded-Proto $scheme;
  proxy_set_header X-Forwarded-For $remote_addr;
 }}
}}
''',0o644)
    enabled=Path('/etc/nginx/sites-enabled/separ-panel')
    if not enabled.exists():enabled.symlink_to('/etc/nginx/sites-available/separ-panel')
    run('nginx','-t');run('systemctl','reload','nginx')
    run('systemctl','daemon-reload')
    if domain:panel_domain(domain,ip,acme)
    run('systemctl','restart','strongswan','openvpn-server@amazon')
    run('systemctl','enable','--now','separ-worker','separ-web','sirgsm-mtg','sirgsm-cert-renew.timer','sirgsm-crl.timer','sirgsm-ike-cert.timer')
    run('systemctl','restart','separ-worker','separ-web')
    ready=False
    for _ in range(40):
        time.sleep(1)
        with database() as db:
            last=get(db,'last_poll','',table='health')
            errors=get(db,'errors',[],table='health')
        if last>=configured_at and not errors:
            code=run('curl','-s','-o','/dev/null','--write-out','%{http_code}','http://127.0.0.1:8099/api/session')
            if code=='401':ready=True;break
    if not ready:raise RuntimeError('Panel readiness check failed: '+str(errors))
    print(f'SirGSM VPN Panel 2: https://{ip}:8443')
    if domain:print(f'Panel domain: https://{domain}:8443')
    print('Fresh-install credentials: /root/sirgsm-admin.txt (existing credentials are preserved on upgrades).')

if __name__=='__main__': main()
