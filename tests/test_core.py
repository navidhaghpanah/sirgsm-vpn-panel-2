import datetime as dt
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

class SetupTests(unittest.TestCase):
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
