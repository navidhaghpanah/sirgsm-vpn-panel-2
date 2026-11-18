import datetime as dt
import base64
import importlib
import os
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'backend'))
os.environ['SEPAR_STATE']=tempfile.mkdtemp(prefix='sirgsm-unit-')
os.environ['SIRGSM_EXPORTS']=tempfile.mkdtemp(prefix='sirgsm-exports-')
import common
from fastapi.testclient import TestClient
from app import app

TEST_PASSWORD='fixture-only-not-a-live-credential-246810'

class PanelTests(unittest.TestCase):
    def setUp(self):
        common.DB=Path(os.environ['SEPAR_STATE'])/'test.db'
        if common.DB.exists():common.DB.unlink()
        common.initialize()
        with common.database() as db:
            common.put(db,'settings','admin_user','admin')
            common.put(db,'settings','admin_hash',common.hash_password(TEST_PASSWORD))
        self.client=TestClient(app,base_url='https://testserver')
        response=self.client.post('/api/login',json={'username':'admin','password':TEST_PASSWORD})
        self.assertEqual(response.status_code,200)
        self.csrf={'X-CSRF-Token':response.json()['csrf']}

    def user(self,name='fixture',**kwargs):
        body={'name':name,'enabled':True,'quota_gb':1,'protocols':list(common.PROTOCOLS),**kwargs}
        response=self.client.post('/api/users',headers=self.csrf,json=body)
        self.assertEqual(response.status_code,201,response.text)
        return response.json()['id'],body

    def test_auth_csrf_and_origin(self):
        anonymous=TestClient(app,base_url='https://testserver')
        self.assertEqual(anonymous.get('/api/dashboard').status_code,401)
        self.assertEqual(self.client.post('/api/users',json={'name':'blocked'}).status_code,403)
        self.assertEqual(self.client.post('/api/users',headers={**self.csrf,'Origin':'https://evil.invalid'},json={'name':'blocked'}).status_code,403)
        response=self.client.get('/api/dashboard')
        self.assertEqual(response.headers['cache-control'],'no-store')
        self.assertIn("frame-ancestors 'none'",response.headers['content-security-policy'])

    def test_unicode_invalid_username_is_rejected_without_server_error(self):
        result=self.client.post('/api/login',json={'username':'نام‌کاربری','password':'wrong'})
        self.assertEqual(result.status_code,401)

    def test_root_configuration_rejects_stored_directive_injection(self):
        valid={'reality':443,'openvpn':2053,'ikev2':'500 / 4500','shadowsocks':8388,'trojan':2087,'vmess':2083}
        self.assertEqual(common.validate_ports(valid),valid)
        for bad in ['2053\nup /var/lib/separ/attacker',True,0,65536,8443]:
            with self.assertRaises(ValueError):common.validate_ports({**valid,'openvpn':bad})

    def test_shared_quota_and_repeated_counters(self):
        uid,_=self.user()
        with common.database() as db:
            common.add_counter(db,'r',uid,'reality',400_000_000)
            common.add_counter(db,'o',uid,'openvpn',300_000_000)
            common.add_counter(db,'i',uid,'ikev2',200_000_000)
            common.add_counter(db,'r',uid,'reality',400_000_000)
            row=db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            self.assertEqual(row['used'],900_000_000)
            self.assertTrue(common.active(row))
            common.add_counter(db,'ss',uid,'shadowsocks',100_000_001)
            row=db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone()
            self.assertFalse(common.active(row));self.assertEqual(common.reason(row),'quota')
        self.assertEqual(self.client.get(f'/api/users/{uid}/export/openvpn').status_code,409)
        result=self.client.get('/api/dashboard').json()['users'][0]
        self.assertNotIn('password',result);self.assertNotIn('uuid',result);self.assertNotIn('cn',result)
        self.assertEqual(sum(result['usage'].values()),result['used'])

    def test_expiry_disabled_and_user_isolation(self):
        expired=(dt.datetime.now(dt.timezone.utc)-dt.timedelta(seconds=10)).isoformat()
        a,_=self.user('expired',expires=expired)
        b,_=self.user('working')
        with common.database() as db:
            common.add_counter(db,'a',a,'trojan',100)
            rows={r['id']:r for r in db.execute('SELECT * FROM users')}
            self.assertEqual(common.reason(rows[a]),'expired')
            self.assertTrue(common.active(rows[b]));self.assertEqual(rows[b]['used'],0)

    def test_validation_and_export_path(self):
        for body in [{'name':'../escape'},{'name':'x','protocols':['unknown']},{'name':'x','expires':'2026-01-01'}]:
            self.assertEqual(self.client.post('/api/users',headers=self.csrf,json=body).status_code,422)
        self.assertEqual(self.client.get('/api/users/'+('f'*32)+'/export/not-allowed').status_code,404)

    def test_authenticated_file_download_is_complete(self):
        uid,_=self.user()
        folder=common.EXPORTS/uid;folder.mkdir()
        expected='fixture-only-test-profile\n'*500
        (folder/'openvpn.ovpn').write_text(expected)
        response=self.client.get(f'/api/users/{uid}/export/openvpn')
        self.assertEqual(response.status_code,200)
        self.assertEqual(response.text,expected)
        self.assertEqual(int(response.headers['content-length']),len(expected))

    @unittest.skipUnless(hasattr(os,'O_NOFOLLOW'),'Linux symlink protection')
    def test_worker_rejects_spool_symlink_without_truncating_target(self):
        import worker
        with tempfile.TemporaryDirectory(prefix='sirgsm-spool-test-') as tmp:
            target=Path(tmp)/'protected';target.write_text('must remain intact')
            spool=Path(tmp)/'events.jsonl';spool.symlink_to(target)
            with common.database() as db,patch.object(worker,'Path',return_value=spool):
                with self.assertRaises(OSError):worker.collect_openvpn(db,[])
            self.assertEqual(target.read_text(),'must remain intact')

    def test_reset_preserves_meter_baseline(self):
        uid,_=self.user()
        with common.database() as db:common.add_counter(db,'counter',uid,'vmess',120)
        self.assertEqual(self.client.post(f'/api/users/{uid}/reset',headers=self.csrf).status_code,200)
        with common.database() as db:
            common.add_counter(db,'counter',uid,'vmess',145)
            self.assertEqual(db.execute('SELECT used FROM users WHERE id=?',(uid,)).fetchone()[0],25)

    def test_login_throttling_and_admin_session_revocation(self):
        other=TestClient(app,base_url='https://testserver')
        for _ in range(8):self.assertEqual(other.post('/api/login',json={'username':'admin','password':'wrong'}).status_code,401)
        self.assertEqual(other.post('/api/login',json={'username':'admin','password':'wrong'}).status_code,429)
        response=self.client.put('/api/admin',headers=self.csrf,json={'current_password':TEST_PASSWORD,'username':'admin2','password':'fixture-only-new-password-13579'})
        self.assertEqual(response.status_code,200)
        self.assertEqual(self.client.get('/api/session').status_code,401)

    def test_vmess_export_uses_domain_sni_with_direct_ip(self):
        import json
        import worker
        uid,_=self.user(protocols=['vmess'])
        with common.database() as db:user=dict(db.execute('SELECT * FROM users WHERE id=?',(uid,)).fetchone())
        settings={'server_ip':'203.0.113.10','ports':{'vmess':2083},'vmess_sni':'vpn.example.com','vmess_port':8443}
        worker.export_user(user,settings)
        uri=(common.EXPORTS/uid/'vmess.txt').read_text().strip()
        profile=json.loads(base64.b64decode(uri.split('://',1)[1]))
        self.assertEqual(profile['add'],'203.0.113.10')
        self.assertEqual(profile['port'],'8443')
        self.assertEqual(profile['sni'],'vpn.example.com')
        self.assertEqual(profile['host'],'vpn.example.com')
        self.assertEqual(profile['alpn'],'http/1.1')
        for bad in ['bad\n.example.com','https://example.com','example.com/path','']:
            with self.assertRaises(ValueError):common.validate_server_name(bad)

    def test_admin_four_digit_password_and_minimum_length(self):
        body={'current_password':TEST_PASSWORD,'username':'admin','password':'482'}
        self.assertEqual(self.client.put('/api/admin',headers=self.csrf,json=body).status_code,422)
        body['password']='4826'
        self.assertEqual(self.client.put('/api/admin',headers=self.csrf,json=body).status_code,200)
        self.assertEqual(self.client.get('/api/session').status_code,401)
        self.assertEqual(self.client.post('/api/login',json={'username':'admin','password':'4826'}).status_code,200)
        with common.database() as db:
            stored=common.get(db,'admin_hash')
            self.assertNotEqual(stored,'4826')
            self.assertTrue(common.check_password('4826',stored))

    def test_private_subscription_rotation_revocation_and_account_limits(self):
        uid,_=self.user(protocols=['reality','openvpn'])
        folder=common.EXPORTS/uid;folder.mkdir()
        link='vless://fixture-only@192.0.2.1:443#fixture'
        (folder/'reality.txt').write_text(link+'\n')
        (folder/'openvpn.ovpn').write_text('fixture-only-profile\n')
        with common.database() as db:db.execute('UPDATE users SET provisioned=1 WHERE id=?',(uid,))
        guest=TestClient(app,base_url='https://testserver')
        self.assertEqual(guest.post(f'/api/users/{uid}/share').status_code,401)
        self.assertEqual(self.client.post(f'/api/users/{uid}/share').status_code,403)
        share=self.client.post(f'/api/users/{uid}/share',headers=self.csrf).json()
        with common.database() as db:common.put(db,'settings','public_origin','https://vpn.example.com:8443')
        canonical=self.client.get(f'/api/users/{uid}/share').json()
        self.assertEqual(canonical['origin'],'https://vpn.example.com:8443')
        path=share['subscription_path'];token=path.rsplit('/',1)[1]
        result=guest.get(path)
        self.assertEqual(result.status_code,200)
        self.assertEqual(base64.b64decode(result.text).decode().strip(),link)
        self.assertEqual(result.headers['cache-control'],'no-store')
        self.assertEqual(result.headers['referrer-policy'],'no-referrer')
        info=guest.get('/api/public/'+token).json()
        for secret in ['password','uuid','cn','id']:self.assertNotIn(secret,info)
        self.assertEqual(guest.get(f'/api/public/{token}/export/openvpn').text,'fixture-only-profile\n')
        self.assertEqual(guest.get(f'/api/public/{token}/export/trojan').status_code,409)
        with common.database() as db:db.execute('UPDATE users SET quota=100,used=101 WHERE id=?',(uid,))
        self.assertEqual(guest.get(path).status_code,403)
        self.assertEqual(guest.get(f'/api/public/{token}/export/openvpn').status_code,409)
        with common.database() as db:db.execute('UPDATE users SET quota=0,expires=? WHERE id=?',('2000-01-01T00:00:00+00:00',uid))
        self.assertEqual(guest.get(path).status_code,403)
        with common.database() as db:db.execute('UPDATE users SET expires=NULL WHERE id=?',(uid,))
        replacement=self.client.post(f'/api/users/{uid}/share',headers=self.csrf).json()
        self.assertEqual(guest.get(path).status_code,404)
        self.assertEqual(guest.get(replacement['subscription_path']).status_code,200)
        self.client.delete(f'/api/users/{uid}/share',headers=self.csrf)
        self.assertEqual(guest.get(replacement['subscription_path']).status_code,404)

class SetupTests(unittest.TestCase):
    def test_bbr_configuration_and_unsupported_kernel(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deploy'))
        import configure
        with patch.object(configure,'run',side_effect=['','reno cubic bbr','','bbr']),patch.object(configure,'write') as write:
            self.assertEqual(configure.configure_tcp_congestion(),'bbr')
            self.assertEqual(write.call_count,2)
            self.assertIn('net.ipv4.tcp_congestion_control=bbr',write.call_args_list[1].args[1])
        with patch.object(configure,'run',side_effect=['','reno cubic']),patch.object(configure,'write') as write:
            self.assertIsNone(configure.configure_tcp_congestion('auto'))
            write.assert_not_called()
        with patch.object(configure,'run',side_effect=['','reno cubic']),patch.object(configure,'write') as write:
            with self.assertRaises(RuntimeError):configure.configure_tcp_congestion('bbr')
            write.assert_not_called()
        with patch.object(configure,'run') as run,patch.object(configure,'write') as write:
            self.assertIsNone(configure.configure_tcp_congestion('keep'))
            run.assert_not_called();write.assert_not_called()

    def test_domain_validation_and_dns_target(self):
        sys.path.insert(0,str(Path(__file__).resolve().parents[1]/'deploy'))
        from configure import validate_domain
        self.assertEqual(validate_domain('VPN.Example.com.','51.20.157.134',resolve=False),'vpn.example.com')
        for value in ['https://vpn.example.com','bad.example;id','a\n.example.com','51.20.157.134','a..com','-x.example.com','*.example.com']:
            with self.assertRaises(ValueError):validate_domain(value,'51.20.157.134',resolve=False)
        with patch('configure.socket.getaddrinfo',return_value=[(2,1,6,'',('51.20.157.134',80))]):
            self.assertEqual(validate_domain('vpn.example.com','51.20.157.134'),'vpn.example.com')
        with patch('configure.socket.getaddrinfo',return_value=[(2,1,6,'',('192.0.2.1',80))]):
            with self.assertRaises(ValueError):validate_domain('vpn.example.com','51.20.157.134')

if __name__=='__main__':unittest.main()
