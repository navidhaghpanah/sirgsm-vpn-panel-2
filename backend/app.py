import datetime as dt
import hashlib
import json
import os
import re
import secrets
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request, Response
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator
from common import STATE, EXPORTS, PROTOCOLS, active, check_password, database, event, get, hash_password, now, put, reason

app=FastAPI(docs_url=None,redoc_url=None,openapi_url=None)
COOKIE='separ_session'
SECURE=os.environ.get('SEPAR_SECURE_COOKIE','1')=='1'

class Login(BaseModel):
    username: str=Field(max_length=64)
    password: str=Field(max_length=256)

class AdminUpdate(BaseModel):
    current_password: str=Field(max_length=256)
    username: str=Field(min_length=3,max_length=50,pattern=r'^[A-Za-z0-9_.-]+$')
    password: str=Field(min_length=16,max_length=256)

class UserInput(BaseModel):
    name: str=Field(min_length=1,max_length=50)
    enabled: bool=True
    quota_gb: float=Field(default=0,ge=0,le=1000000,allow_inf_nan=False)
    expires: str | None=None
    protocols: list[str]=Field(default_factory=lambda:list(PROTOCOLS))

    @field_validator('name')
    def validate_name(cls,v):
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.-]{0,49}',v):
            raise ValueError('نام کاربر باید انگلیسی و بدون فاصله باشد')
        return v

    @field_validator('protocols')
    def validate_protocols(cls,v):
        if not v or len(set(v)) != len(v) or any(x not in PROTOCOLS for x in v):
            raise ValueError('سرویس نامعتبر است')
        return v

    @field_validator('expires')
    def validate_expires(cls,v):
        if not v: return None
        d=dt.datetime.fromisoformat(v.replace('Z','+00:00'))
        if d.tzinfo is None: raise ValueError('timezone required')
        return d.astimezone(dt.timezone.utc).isoformat()

def authenticate(request):
    token=request.cookies.get(COOKIE,'')
    with database() as db:
        row=db.execute('SELECT * FROM sessions WHERE token=? AND expires>?',
                       (hashlib.sha256(token.encode()).hexdigest(),int(time.time()))).fetchone()
    if not row: raise HTTPException(401,'ابتدا وارد شوید')
    if request.method not in ('GET','HEAD') and not secrets.compare_digest(request.headers.get('x-csrf-token','').encode(),row['csrf'].encode()):
        raise HTTPException(403,'درخواست معتبر نیست')
    return row

class SecurityHeaders:
    """Pure ASGI middleware preserves streaming and file-transfer messages."""
    def __init__(self,app):self.app=app
    async def __call__(self,scope,receive,send):
        if scope['type']!='http':return await self.app(scope,receive,send)
        headers={k.decode().lower():v.decode() for k,v in scope.get('headers',[])}
        if scope['method'] not in ('GET','HEAD'):
            origin=headers.get('origin')
            expected=scope['scheme']+'://'+headers.get('host','')
            if origin and origin!=expected:
                return await Response(status_code=403)(scope,receive,send)
        async def send_headers(message):
            if message['type']=='http.response.start':
                extra=[(b'x-content-type-options',b'nosniff'),(b'x-frame-options',b'DENY'),(b'referrer-policy',b'no-referrer'),
                  (b'content-security-policy',b"default-src 'self'; script-src 'self'; style-src 'self'; font-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'")]
                if scope['path'].startswith('/api/'):extra.append((b'cache-control',b'no-store'))
                message={**message,'headers':list(message.get('headers',[]))+extra}
            await send(message)
        await self.app(scope,receive,send_headers)

app.add_middleware(SecurityHeaders)

@app.post('/api/login')
def login(body: Login,request: Request,response: Response):
    ip=request.client.host
    instant=int(time.time())
    with database() as db:
        attempt=db.execute('SELECT * FROM login_attempts WHERE ip=?',(ip,)).fetchone()
        if attempt and attempt['count']>=8 and attempt['until']>instant:
            raise HTTPException(429,'چند دقیقه بعد دوباره تلاش کنید')
        valid=secrets.compare_digest(body.username.encode(),get(db,'admin_user','admin').encode()) and check_password(body.password,get(db,'admin_hash',''))
        if not valid:
            count=attempt['count']+1 if attempt and attempt['until']>instant else 1
            db.execute('INSERT OR REPLACE INTO login_attempts VALUES(?,?,?)',(ip,count,instant+600))
        else:
            db.execute('DELETE FROM login_attempts WHERE ip=?',(ip,))
            db.execute('DELETE FROM sessions WHERE expires<?',(instant,))
            token=secrets.token_urlsafe(40); csrf=secrets.token_urlsafe(24)
            db.execute('INSERT INTO sessions VALUES(?,?,?)',(hashlib.sha256(token.encode()).hexdigest(),instant+43200,csrf))
            event(db,'login','ورود مدیر')
    if not valid: raise HTTPException(401,'نام کاربری یا رمز اشتباه است')
    response.set_cookie(COOKIE,token,httponly=True,secure=SECURE,samesite='strict',max_age=43200)
    return {'csrf':csrf}

@app.get('/api/session')
def session(request: Request): return {'csrf':authenticate(request)['csrf']}

@app.post('/api/logout')
def logout(request: Request,response: Response):
    authenticate(request)
    with database() as db: db.execute('DELETE FROM sessions WHERE token=?',(hashlib.sha256(request.cookies[COOKIE].encode()).hexdigest(),))
    response.delete_cookie(COOKIE)
    return {'ok':True}

@app.put('/api/admin')
def update_admin(body: AdminUpdate,request: Request,response: Response):
    authenticate(request)
    with database() as db:
        if not check_password(body.current_password,get(db,'admin_hash','')): raise HTTPException(403,'رمز فعلی اشتباه است')
        put(db,'settings','admin_user',body.username)
        put(db,'settings','admin_hash',hash_password(body.password))
        db.execute('DELETE FROM sessions')
        event(db,'admin','نام کاربری یا رمز مدیر تغییر کرد؛ نشست‌های قبلی باطل شدند')
    response.delete_cookie(COOKIE)
    return {'ok':True}

def public_user(row,db):
    u=dict(row)
    for key in ('uuid','password','cn'): u.pop(key)
    u['protocols']=json.loads(u['protocols']); u['status']=reason(row)
    u['usage']={r['protocol']:r['bytes'] for r in db.execute('SELECT * FROM usage WHERE user_id=?',(u['id'],))}
    return u

@app.get('/api/dashboard')
def dashboard(request: Request):
    authenticate(request)
    with database() as db:
        users=[public_user(row,db) for row in db.execute('SELECT * FROM users WHERE deleted=0 ORDER BY created')]
        health={row['key']:json.loads(row['value']) for row in db.execute('SELECT * FROM health')}
        events=[dict(row) for row in db.execute('SELECT * FROM events ORDER BY id DESC LIMIT 80')]
        server=get(db,'server_ip','')
        ports=get(db,'ports',{'reality':443,'openvpn':2053,'ikev2':'500 / 4500','shadowsocks':8388,'trojan':2087,'vmess':2083})
    return {'users':users,'health':health,'events':events,'server':server,'ports':ports,'accounting_interval':5}

@app.get('/api/telegram')
def telegram(request: Request):
    authenticate(request)
    with database() as db:
        info=get(db,'telegram')
    if not info: raise HTTPException(404,'Telegram is not installed')
    return {'url':info['url'],'direct_url':info['direct_url'],'quota':'independent'}

@app.post('/api/users',status_code=201)
def create_user(body: UserInput,request: Request):
    authenticate(request)
    uid=uuid.uuid4().hex
    with database() as db:
        if db.execute('SELECT 1 FROM users WHERE name=?',(body.name,)).fetchone(): raise HTTPException(409,'این نام قبلاً استفاده شده است')
        db.execute('INSERT INTO users(id,name,enabled,quota,expires,protocols,uuid,password,cn,created) VALUES(?,?,?,?,?,?,?,?,?,?)',
                   (uid,body.name,int(body.enabled),round(body.quota_gb*10**9),body.expires,json.dumps(body.protocols),str(uuid.uuid4()),secrets.token_urlsafe(24),'u'+uid,now()))
        event(db,'user',f'کاربر {body.name} ایجاد شد')
    return {'id':uid}

@app.put('/api/users/{uid}')
def update_user(uid: str,body: UserInput,request: Request):
    authenticate(request)
    with database() as db:
        if not db.execute('SELECT 1 FROM users WHERE id=? AND deleted=0',(uid,)).fetchone(): raise HTTPException(404)
        if db.execute('SELECT 1 FROM users WHERE name=? AND id<>?',(body.name,uid)).fetchone(): raise HTTPException(409,'نام تکراری')
        db.execute('UPDATE users SET name=?,enabled=?,quota=?,expires=?,protocols=?,provisioned=0 WHERE id=?',
                   (body.name,int(body.enabled),round(body.quota_gb*10**9),body.expires,json.dumps(body.protocols),uid))
        event(db,'user',f'تنظیمات کاربر {body.name} تغییر کرد')
    return {'ok':True}

@app.post('/api/users/{uid}/reset')
def reset(uid: str,request: Request):
    authenticate(request)
    with database() as db:
        row=db.execute('SELECT name FROM users WHERE id=? AND deleted=0',(uid,)).fetchone()
        if not row: raise HTTPException(404)
        db.execute('UPDATE users SET used=0 WHERE id=?',(uid,))
        db.execute('UPDATE usage SET bytes=0 WHERE user_id=?',(uid,))
        event(db,'user',f'مصرف کاربر {row[0]} صفر شد')
    return {'ok':True}

@app.delete('/api/users/{uid}')
def delete(uid: str,request: Request):
    authenticate(request)
    with database() as db:
        row=db.execute('SELECT name FROM users WHERE id=? AND deleted=0',(uid,)).fetchone()
        if not row: raise HTTPException(404)
        db.execute('UPDATE users SET deleted=1,enabled=0 WHERE id=?',(uid,))
        event(db,'user',f'کاربر {row[0]} حذف شد')
    return {'ok':True}

@app.get('/api/users/{uid}/export/{kind}')
def export(uid: str,kind: str,request: Request):
    authenticate(request)
    suffix={'reality':'txt','openvpn':'ovpn','ikev2':'txt','ios':'mobileconfig','ca':'cer','shadowsocks':'txt','trojan':'txt','vmess':'txt'}.get(kind)
    if not suffix or not re.fullmatch('[a-f0-9]{32}',uid): raise HTTPException(404)
    with database() as db:
        row=db.execute('SELECT * FROM users WHERE id=? AND deleted=0',(uid,)).fetchone()
        if not row: raise HTTPException(404)
        if not active(row): raise HTTPException(409,'این حساب فعال نیست')
        protocol='ikev2' if kind in ('ios','ca') else kind
        if protocol not in json.loads(row['protocols']): raise HTTPException(409,'این سرویس برای کاربر فعال نیست')
    path=EXPORTS/uid/(kind+'.'+suffix)
    if not path.is_file(): raise HTTPException(409,'کانفیگ هنوز آماده نشده؛ چند ثانیه صبر کنید')
    return FileResponse(path,filename=f'SirGSM-{row["name"]}-{kind}.{suffix}')

dist=Path(os.environ.get('SEPAR_DIST','/opt/separ/frontend/dist'))
if dist.is_dir(): app.mount('/',StaticFiles(directory=dist,html=True),name='frontend')
