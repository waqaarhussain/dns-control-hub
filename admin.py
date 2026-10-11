"""Private console API. Cookie sessions, CSRF checks and no public management keys."""
import base64
import getpass
import hashlib
import hmac
import json
import os
import re
import secrets
import socket
import threading
import time
from pathlib import Path
import hub
import devices
import profiles

sessions={}; failures={}; lock=threading.Lock()

def merge_appearance(data):
    if not isinstance(data,dict) or set(data)!={'revision','title','message'} or type(data['revision']) is not int or data['revision']<1 or not isinstance(data['title'],str) or not 1<=len(data['title'])<=100 or not isinstance(data['message'],str) or not 1<=len(data['message'])<=500:
        raise ValueError('Invalid block-page settings.')
    with devices.locked():
        path=hub.ROOT/'control/appearance.json'
        current=hub.load(path) if path.exists() else None
        if current is None or data['revision']>current.get('revision',0):
            profiles.atomic(path,data);return data
        return current

def password_record(password):
    salt=secrets.token_bytes(24)
    digest=hashlib.pbkdf2_hmac('sha256',password.encode(),salt,600000)
    return dict(salt=salt.hex(),hash=digest.hex())

def matches(password, record):
    value=hashlib.pbkdf2_hmac('sha256',password.encode(),bytes.fromhex(record['salt']),600000)
    return hmac.compare_digest(value.hex(),record['hash'])

def setup():
    path=hub.ROOT/'control/admin-auth.json'
    if path.exists(): return
    node=hub.load(hub.ROOT/'node.json')
    password=node.get('admin_password') if node.get('console_ready') else None
    if not password:
        print('Choose your dashboard password. Username: admin. Input is hidden.')
        password=getpass.getpass('New dashboard password (at least 12 characters): ')
        if len(password)<12 or password!=getpass.getpass('Confirm dashboard password: '):
            raise ValueError('Passwords must match and have at least 12 characters.')
    hub.write(path,json.dumps(password_record(password)))
    node.pop('admin_password',None);node['engine']='unbound';node['console_ready']=True
    hub.write(hub.ROOT/'node.json',json.dumps(node,indent=2))
    print('Dashboard account ready. Username admin; your saved password is retained when migrating.')

def session(handler):
    cookies={}
    for item in handler.headers.get('Cookie','').split(';'):
        if '=' in item:
            key,value=item.strip().split('=',1);cookies[key]=value
    token=cookies.get('__Host-dns_session','')
    with lock:
        for old in list(sessions):
            if sessions[old]['expires']<time.time(): sessions.pop(old)
        return token,sessions.get(token)

def reply(handler,code,data,cookie=None):
    content=json.dumps(data).encode()
    handler.send_response(code);handler.send_header('Content-Type','application/json')
    handler.send_header('Cache-Control','no-store');handler.send_header('Content-Length',str(len(content)))
    if cookie: handler.send_header('Set-Cookie',cookie)
    handler.end_headers();handler.wfile.write(content)

def static(handler, path):
    allowed={'/':'index.html','/app.js':'app.js','/app.css':'app.css','/assets/ui.css':'assets/ui.css','/assets/tokens.css':'assets/tokens.css','/assets/icons.svg':'assets/icons.svg'}
    name=allowed.get(path)
    if name is None or handler.command!='GET': return False
    content=(hub.SOURCE/'web'/name).read_bytes()
    kind='text/html; charset=utf-8' if name.endswith('.html') else 'text/css' if name.endswith('.css') else 'image/svg+xml' if name.endswith('.svg') else 'application/javascript'
    handler.reply(200,content,kind);return True

def state():
    settings=hub.load(hub.ROOT/'shared/settings.json'); node=hub.load(hub.ROOT/'node.json')
    items=profiles.ensure()['profiles']
    registry=devices.snapshot()
    members=[dict(id=d['id'],name=d['name'],type=d['type'],profile=d.get('profile','default'),blocked=d['blocked'],download_url='https://'+settings['hostname']+'/profiles/'+d['download_token']+'/dns.mobileconfig') for d in registry.values()]
    available={}
    for category in profiles.CATEGORIES:
        path=hub.ROOT/'control/category-lists'/(category+'.txt')
        available[category]=dict(ready=path.exists(),updated=path.stat().st_mtime if path.exists() else None)
    hostname,port=os.environ.get('DNS_HUB_RESOLVER','dns:5353').rsplit(':',1)
    try:
        with socket.create_connection((hostname,int(port)),timeout=0.5): resolver=True
    except OSError: resolver=False
    appearance=hub.ROOT/'control/appearance.json'
    return dict(profiles=items,devices=members,categories=available,hostname=settings['hostname'],ip=node['public_ip'],resolver_ready=resolver,
        controller=node['public_ip']==settings['dns_ips'][0],paired=len(settings['dns_ips'])==2,
        appearance=hub.load(appearance) if appearance.exists() else dict(title='This website is blocked',message='Your DNS rules have restricted access to this website.'),
        youtube_ip=hub.ALBANIA_IP)

def mutate(action, data):
    settings=hub.load(hub.ROOT/'shared/settings.json');node=hub.load(hub.ROOT/'node.json')
    if node['public_ip']!=settings['dns_ips'][0]: raise ValueError('Manage profiles and devices on the first DNS VPS.')
    if action=='device/new':
        device=devices.create_device(data['name'],data['type'],data['profile'],export=False)
    elif action=='device/update':
        with devices.locked():
            registry=devices.registry_unlocked();device=registry[data['id']]
            if 'profile' in data:
                policy_path=hub.ROOT/'control/profiles.json'
                if data['profile'] not in hub.load(policy_path)['profiles']: raise ValueError('Unknown profile.')
                device['profile']=data['profile']
            if 'blocked' in data:
                if type(data['blocked']) is not bool: raise ValueError('Invalid device status.')
                device['blocked']=data['blocked']
            device['revision']=max(time.time_ns(),device['revision']+1);devices.save(registry)
    elif action=='profile/save':
        key=data.get('id') or re.sub(r'[^a-z0-9_-]+','-',data['name'].lower()).strip('-_')[:64]
        if not key: raise ValueError('Enter a profile name containing letters or numbers.')
        def change(items):
            if not data.get('id') and key in items: raise ValueError('Profile already exists.')
            existing=items.get(key,dict(blocked_sites=[],allowed_sites=[]))
            items[key]=dict(name=data['name'],categories=data['categories'],blocked_sites=existing['blocked_sites'],allowed_sites=existing['allowed_sites'])
        profiles.edit(change, sync=False)
    elif action=='site':
        domain=profiles.normalize_site(data['site']); mode=data['mode']; keys=data['profiles']
        if mode not in ('block','allow','remove') or not isinstance(keys,list) or not keys: raise ValueError('Select profiles and a rule action.')
        def change(items):
            for key in keys:
                if key not in items: raise ValueError('Unknown profile.')
                item=items[key]
                for field in ('blocked_sites','allowed_sites'): item[field]=[x for x in item[field] if x!=domain]
                if mode!='remove':
                    field='blocked_sites' if mode=='block' else 'allowed_sites'
                    item[field]=sorted(set(item[field])|{domain})
        profiles.edit(change, sync=False)
    elif action=='appearance':
        title=data['title'].strip();message=data['message'].strip()
        if not 1<=len(title)<=100 or not 1<=len(message)<=500: raise ValueError('Enter a title and message within the displayed limits.')
        merge_appearance(dict(revision=time.time_ns(),title=title,message=message))
    else: raise ValueError('Unknown dashboard action.')
    synced=True
    try: devices.sync_peer()
    except (OSError,ValueError,RuntimeError): synced=False
    return dict(ok=True,synced=synced)

def route(handler, parsed):
    if static(handler,parsed.path): return True
    prefix='/api/console/'
    if not parsed.path.startswith(prefix): return False
    action=parsed.path[len(prefix):]
    try:
        data=json.loads(handler.body(64000)) if handler.command=='POST' else {}
        if not isinstance(data,dict): raise ValueError('Invalid request.')
        settings=hub.load(hub.ROOT/'shared/settings.json')
        origin='https://'+settings['hostname']
        if handler.command=='POST' and handler.headers.get('Origin')!=origin:
            reply(handler,403,dict(error='Request origin rejected.'));return True
        if action=='login' and handler.command=='POST':
            ip=handler.headers.get('X-Real-IP',handler.client_address[0])
            with lock:
                now=time.time(); history=[x for x in failures.get(ip,[]) if x>now-60]
                if len(history)>=5:
                    reply(handler,429,dict(error='Too many login attempts. Try again in a minute.'));return True
                history.append(now);failures[ip]=history
                if len(failures)>10000: failures.clear()
            path=hub.ROOT/'control/admin-auth.json'
            if not path.exists():
                reply(handler,503,dict(error='Dashboard account not initialized. Run the installer.'));return True
            password=data.get('password','')
            if not isinstance(password,str) or len(password)>1024 or data.get('username')!='admin' or not matches(password,hub.load(path)):
                reply(handler,401,dict(error='Incorrect username or password.'));return True
            token=secrets.token_hex(32);csrf=secrets.token_hex(32)
            with lock:
                if len(sessions)>50: sessions.clear()
                sessions[token]=dict(csrf=csrf,expires=time.time()+28800)
                failures.pop(ip,None)
            reply(handler,200,dict(csrf=csrf),'__Host-dns_session='+token+'; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=28800');return True
        token,current=session(handler)
        if current is None:
            reply(handler,401,dict(error='Please sign in.'));return True
        if handler.command=='GET' and action=='state':
            reply(handler,200,dict(**state(),csrf=current['csrf']));return True
        if handler.command!='POST':
            reply(handler,405,dict(error='Use POST for this action.'));return True
        if not hmac.compare_digest(handler.headers.get('X-CSRF-Token',''),current['csrf']):
            reply(handler,403,dict(error='Request verification failed.'));return True
        if action=='logout':
            with lock: sessions.pop(token,None)
            reply(handler,200,dict(ok=True),'__Host-dns_session=; Secure; HttpOnly; SameSite=Strict; Path=/; Max-Age=0');return True
        if action=='password':
            path=hub.ROOT/'control/admin-auth.json';password=data['password']
            if not isinstance(password,str) or not 12<=len(password)<=1024 or not matches(data['current'],hub.load(path)): raise ValueError('Check the current password; the new password needs at least 12 characters.')
            with devices.locked(): profiles.atomic(path,password_record(password))
            with lock: sessions.clear()
            reply(handler,200,dict(ok=True));return True
        reply(handler,200,mutate(action,data));return True
    except (ValueError,KeyError,TypeError):
        reply(handler,400,dict(error='Invalid input. Check names, profiles and required fields.'));return True
    except (OSError,RuntimeError):
        reply(handler,503,dict(error='The service is temporarily unavailable. Check the server logs.'));return True
