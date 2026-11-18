"""Private bearer links: administrator-controlled, independently revocable."""
import base64
import datetime as dt
import json
import re
import secrets

from fastapi import APIRouter,HTTPException,Request,Response
from fastapi.responses import FileResponse
from common import EXPORTS,active,database,event,reason,get

KINDS={'reality':'txt','openvpn':'ovpn','ikev2':'txt','ios':'mobileconfig','ca':'cer','shadowsocks':'txt','trojan':'txt','vmess':'txt'}
XRAY=('reality','shadowsocks','trojan','vmess')

def export_response(row,kind):
    suffix=KINDS.get(kind)
    if not suffix:raise HTTPException(404)
    if not active(row):raise HTTPException(409,'Account is inactive')
    if not row['provisioned']:raise HTTPException(409,'Configuration is being prepared; retry shortly')
    protocol='ikev2' if kind in ('ios','ca') else kind
    if protocol not in json.loads(row['protocols']):raise HTTPException(409,'Service is not enabled for this account')
    if not re.fullmatch('[a-f0-9]{32}',row['id']):raise HTTPException(404)
    path=EXPORTS/row['id']/(kind+'.'+suffix)
    if not path.is_file():raise HTTPException(409,'Configuration is not ready')
    return FileResponse(path,filename=f'SirGSM-{row["name"]}-{kind}.{suffix}')

def token_user(token):
    if not re.fullmatch(r'[A-Za-z0-9_-]{43}',token):raise HTTPException(404)
    with database() as db:
        row=db.execute('SELECT u.* FROM users u JOIN subscriptions s ON s.user_id=u.id WHERE s.token=? AND u.deleted=0',(token,)).fetchone()
    if not row:raise HTTPException(404)
    return row

def share_paths(token):
    with database() as db:origin=get(db,'public_origin','')
    return {'page_path':'/u/'+token,'subscription_path':'/sub/'+token,'origin':origin}

def make_router(authenticate,dist):
    router=APIRouter()

    def managed_user(db,uid):
        if not re.fullmatch('[a-f0-9]{32}',uid):raise HTTPException(404)
        row=db.execute('SELECT * FROM users WHERE id=? AND deleted=0',(uid,)).fetchone()
        if not row:raise HTTPException(404)
        return row

    @router.get('/api/users/{uid}/share')
    def get_share(uid:str,request:Request):
        authenticate(request)
        with database() as db:
            managed_user(db,uid)
            row=db.execute('SELECT token FROM subscriptions WHERE user_id=?',(uid,)).fetchone()
        return share_paths(row['token']) if row else None

    @router.post('/api/users/{uid}/share')
    def create_share(uid:str,request:Request):
        authenticate(request)
        with database() as db:
            managed_user(db,uid)
            token=secrets.token_urlsafe(32)
            db.execute('INSERT INTO subscriptions(user_id,token) VALUES(?,?) ON CONFLICT(user_id) DO UPDATE SET token=excluded.token',(uid,token))
            event(db,'share','Private user link created or rotated')
        return share_paths(token)

    @router.delete('/api/users/{uid}/share')
    def revoke_share(uid:str,request:Request):
        authenticate(request)
        with database() as db:
            managed_user(db,uid)
            db.execute('DELETE FROM subscriptions WHERE user_id=?',(uid,))
            event(db,'share','Private user link revoked')
        return {'ok':True}

    @router.get('/u/{token}')
    def landing(token:str):
        token_user(token)
        path=dist/'index.html'
        if not path.is_file():raise HTTPException(503)
        return FileResponse(path)

    @router.get('/api/public/{token}')
    def user_info(token:str):
        row=token_user(token)
        return {'name':row['name'],'status':reason(row),'used':row['used'],'quota':row['quota'],
                'expires':row['expires'],'protocols':json.loads(row['protocols']),'ready':bool(row['provisioned']),**share_paths(token)}

    @router.get('/api/public/{token}/export/{kind}')
    def public_export(token:str,kind:str):return export_response(token_user(token),kind)

    @router.get('/sub/{token}')
    def subscription(token:str):
        row=token_user(token)
        if not active(row):raise HTTPException(403,'Account is inactive')
        if not row['provisioned']:raise HTTPException(409,'Configuration is not ready')
        if not re.fullmatch('[a-f0-9]{32}',row['id']):raise HTTPException(404)
        links=[]
        for kind in XRAY:
            if kind not in json.loads(row['protocols']):continue
            path=EXPORTS/row['id']/(kind+'.txt')
            if not path.is_file():raise HTTPException(409,'Configuration is not ready')
            links.append(path.read_text().strip())
        if not links:raise HTTPException(409,'No Xray services are enabled; download OpenVPN or IKEv2 from the user page')
        info=f'upload=0; download={row["used"]}; total={row["quota"]}'
        if row['expires']:info+='; expire='+str(int(dt.datetime.fromisoformat(row['expires']).timestamp()))
        return Response(base64.b64encode(('\n'.join(links)+'\n').encode()).decode(),media_type='text/plain',
                        headers={'subscription-userinfo':info,'profile-update-interval':'12',
                                 'profile-title':'base64:'+base64.b64encode(('SirGSM-'+row['name']).encode()).decode()})

    return router
