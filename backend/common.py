import contextlib
import datetime as dt
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
from pathlib import Path

STATE = Path(os.environ.get('SEPAR_STATE', '/var/lib/separ'))
DB = STATE / 'panel.db'
EXPORTS = Path(os.environ.get('SIRGSM_EXPORTS','/var/lib/separ-exports'))
PROTOCOLS = ('reality', 'openvpn', 'ikev2', 'shadowsocks', 'trojan', 'vmess')

def validate_ports(value):
    keys={'reality','openvpn','shadowsocks','trojan','vmess'}
    if not isinstance(value,dict) or set(value)!=keys|{'ikev2'}:
        raise ValueError('Invalid protocol port settings')
    ports={key:value[key] for key in keys}
    if any(type(port) is not int or not 1<=port<=65535 or port in {22,80,8443,2096,8099,10085,3129} for port in ports.values()):
        raise ValueError('Protocol ports must be safe integer port numbers')
    if len(set(ports.values()))!=len(ports):raise ValueError('Protocol ports must be distinct')
    if value['ikev2']!='500 / 4500':raise ValueError('Invalid IKEv2 port setting')
    return dict(value)

@contextlib.contextmanager
def database():
    db = sqlite3.connect(DB, timeout=20)
    db.row_factory = sqlite3.Row
    db.execute('PRAGMA foreign_keys=ON')
    try:
        yield db
        db.commit()
    except Exception:
        db.rollback()
        raise
    finally:
        db.close()

def initialize():
    STATE.mkdir(parents=True, exist_ok=True)
    with database() as db:
        db.execute('PRAGMA journal_mode=WAL')
        db.executescript('''
        CREATE TABLE IF NOT EXISTS settings(key TEXT PRIMARY KEY, value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS users(
          id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, enabled INTEGER NOT NULL DEFAULT 1,
          quota INTEGER NOT NULL DEFAULT 0, expires TEXT, protocols TEXT NOT NULL,
          uuid TEXT NOT NULL, password TEXT NOT NULL, cn TEXT UNIQUE NOT NULL,
          used INTEGER NOT NULL DEFAULT 0, provisioned INTEGER NOT NULL DEFAULT 0,
          deleted INTEGER NOT NULL DEFAULT 0, created TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS usage(user_id TEXT, protocol TEXT, bytes INTEGER NOT NULL DEFAULT 0,
          PRIMARY KEY(user_id,protocol));
        CREATE TABLE IF NOT EXISTS counters(key TEXT PRIMARY KEY,user_id TEXT,protocol TEXT,value INTEGER NOT NULL);
        CREATE TABLE IF NOT EXISTS sessions(token TEXT PRIMARY KEY,expires INTEGER NOT NULL,csrf TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS events(id INTEGER PRIMARY KEY AUTOINCREMENT,at TEXT NOT NULL,kind TEXT NOT NULL,message TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS health(key TEXT PRIMARY KEY,value TEXT NOT NULL);
        CREATE TABLE IF NOT EXISTS login_attempts(ip TEXT PRIMARY KEY,count INTEGER NOT NULL,until INTEGER NOT NULL);
        ''')

def now():
    return dt.datetime.now(dt.timezone.utc).isoformat()

def active(user, instant=None):
    instant = instant or now()
    return bool(user['enabled'] and not user['deleted'] and
                (not user['quota'] or user['used'] < user['quota']) and
                (not user['expires'] or user['expires'] > instant))

def reason(user):
    if user['deleted'] or not user['enabled']: return 'disabled'
    if user['expires'] and user['expires'] <= now(): return 'expired'
    if user['quota'] and user['used'] >= user['quota']: return 'quota'
    return 'active'

def event(db, kind, message):
    db.execute('INSERT INTO events(at,kind,message) VALUES(?,?,?)', (now(),kind,message))

def put(db, table, key, value):
    if table not in ('settings', 'health'): raise ValueError('invalid table')
    db.execute(f'INSERT OR REPLACE INTO {table}(key,value) VALUES(?,?)',(key,json.dumps(value)))

def get(db, key, default=None, table='settings'):
    if table not in ('settings', 'health'): raise ValueError('invalid table')
    row=db.execute(f'SELECT value FROM {table} WHERE key=?',(key,)).fetchone()
    return json.loads(row[0]) if row else default

def hash_password(password, salt=None):
    salt = salt or secrets.token_hex(16)
    value=hashlib.scrypt(password.encode(),salt=salt.encode(),n=16384,r=8,p=1).hex()
    return salt+':'+value

def check_password(password, stored):
    try: return hmac.compare_digest(hash_password(password,stored.split(':')[0]),stored)
    except (ValueError,TypeError): return False

def add_counter(db, key, user_id, protocol, value, absolute=True):
    value=max(0,int(value))
    if absolute:
        old=db.execute('SELECT value FROM counters WHERE key=?',(key,)).fetchone()
        delta=value-old[0] if old and value >= old[0] else value
        db.execute('INSERT OR REPLACE INTO counters VALUES(?,?,?,?)',(key,user_id,protocol,value))
    else: delta=value
    db.execute('UPDATE users SET used=used+? WHERE id=?',(delta,user_id))
    db.execute('INSERT INTO usage(user_id,protocol,bytes) VALUES(?,?,?) ON CONFLICT(user_id,protocol) DO UPDATE SET bytes=bytes+excluded.bytes',(user_id,protocol,delta))
    return delta
