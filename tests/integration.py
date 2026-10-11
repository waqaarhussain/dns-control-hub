"""Docker smoke tests with disposable credentials and a private test CA."""
import datetime
import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import sys
import time
sys.path.insert(0,str(Path(__file__).parents[1]))
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID
import hub
import profiles
import stack

HOST='dns.integration.example'
PASSWORD='disposable-integration-password'

def prepare():
    root=hub.ROOT;root.mkdir(parents=True,exist_ok=True)
    (root/'source').symlink_to(hub.SOURCE,target_is_directory=True)
    settings=dict(hostname=HOST,dns_ips=['8.8.8.8'],proxy_ip=hub.ALBANIA_IP,management_key=secrets.token_hex(32),endpoint_key=secrets.token_hex(32),acme_email='integration@example.com')
    hub.write(root/'shared/settings.json',json.dumps(settings))
    hub.write(root/'node.json',json.dumps(dict(public_ip='8.8.8.8',admin_password=PASSWORD,console_ready=True)))
    key=rsa.generate_private_key(65537,2048)
    name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Disposable integration CA')])
    now=datetime.datetime.now(datetime.timezone.utc)
    ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
    (root/'shared/ca.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
    (root/'shared/ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (root/'shared/ca.der').write_bytes(ca.public_bytes(serialization.Encoding.DER))
    (root/'shared/ca.p12').write_bytes(pkcs12.serialize_key_and_certificates(b'ca',key,ca,None,serialization.NoEncryption()))
    tls=root/'tls';tls.mkdir()
    cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,HOST)])).issuer_name(ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(hours=1)).not_valid_after(now+datetime.timedelta(days=1)).add_extension(x509.SubjectAlternativeName([x509.DNSName(HOST)]),False).sign(key,hashes.SHA256()))
    (tls/'key.pem').write_bytes((root/'shared/ca.key').read_bytes())
    (tls/'fullchain.pem').write_bytes(cert.public_bytes(serialization.Encoding.PEM)+ca.public_bytes(serialization.Encoding.PEM))
    directory=root/'control/category-lists';directory.mkdir(parents=True)
    for category in profiles.CATEGORIES:
        names=[f'{category}{i}.fixture.example' for i in range(100)]
        if category=='gambling': names.append('bets.fixture.example')
        (directory/(category+'.txt')).write_text('\n'.join(sorted(names))+'\n')
    stack.render()
    with (root/'unbound.conf').open('a') as out:
        for domain in ('example.com','fixture.example'):
            out.write(f'  local-zone: "{domain}." redirect\n  local-data: "{domain}. 0 IN A 93.184.216.34"\n')

class LocalTLS(http.client.HTTPSConnection):
    def connect(self):
        raw=socket.create_connection(('127.0.0.1',443),self.timeout)
        self.sock=self._context.wrap_socket(raw,server_hostname=self.host)

def request(path,body=None,headers=None,host=HOST):
    context=ssl.create_default_context(cafile=str(hub.ROOT/'shared/ca.crt'))
    connection=LocalTLS(host,context=context,timeout=15)
    try:
        connection.request('POST' if body is not None else 'GET',path,body=body,headers=headers or {})
        response=connection.getresponse();return response.status,dict(response.getheaders()),response.read()
    finally: connection.close()

def check():
    for attempt in range(60):
        try:
            if request('/')[0]==200: break
        except (OSError,http.client.HTTPException): pass
        time.sleep(1)
    else: raise RuntimeError('Containers did not become ready.')
    os.environ['CURL_CA_BUNDLE']=str(hub.ROOT/'shared/ca.crt')
    stack.check()
    status,headers,body=request('/api/console/login',json.dumps(dict(username='admin',password=PASSWORD)).encode(),{'Content-Type':'application/json','Origin':'https://'+HOST})
    assert status==200, (status,body)
    csrf=json.loads(body)['csrf'];cookie=headers['Set-Cookie'].split(';',1)[0]
    def api(path,data):
        status,_,body=request('/api/console/'+path,json.dumps(data).encode(),{'Content-Type':'application/json','Origin':'https://'+HOST,'Cookie':cookie,'X-CSRF-Token':csrf})
        assert status==200,(path,status,body)
        return json.loads(body)
    for name,profile in [('Adult test phone','adults'),('Kid test phone','kids')]: api('device/new',dict(name=name,type='iOS',profile=profile))
    status,_,body=request('/api/console/state',headers={'Cookie':cookie})
    data=json.loads(body);assert status==200 and data['resolver_ready']
    assert hub.load(hub.ROOT/'shared/settings.json')['management_key'] not in body.decode()
    # Look up the private tokens from the disposable server state only.
    registry=hub.load(hub.ROOT/'control/devices.json')
    devices={d['profile']:d for d in registry.values()}
    def resolve(device,name,kind=1):
        packet=hub.dns_query(name)[:-4]+struct.pack('!HH',kind,1)
        status,_,answer=request('/dns/'+device['token']+'/dns-query',packet,{'Content-Type':'application/dns-message'})
        assert status==200
        return answer
    blocked=ipaddress.IPv4Address('8.8.8.8').packed
    real=ipaddress.IPv4Address('93.184.216.34').packed
    assert resolve(devices['kids'],'bets.fixture.example').endswith(blocked)
    assert real in resolve(devices['adults'],'bets.fixture.example')[12:]
    for kind in (28,64,65): assert struct.unpack('!6H',resolve(devices['adults'],'www.youtube.com',kind)[:12])[3]==0
    assert resolve(devices['adults'],'r1.googlevideo.com').endswith(ipaddress.IPv4Address(hub.ALBANIA_IP).packed)
    api('site',dict(site='bets.fixture.example',mode='allow',profiles=['kids']))
    assert real in resolve(devices['kids'],'bets.fixture.example')[12:]
    api('device/update',dict(id=devices['kids']['id'],blocked=True))
    for kind in (1,28,15,65): assert struct.unpack('!6H',resolve(devices['kids'],'example.com',kind)[:12])[1]&15==5
    api('device/update',dict(id=devices['kids']['id'],blocked=False))
    assert real in resolve(devices['kids'],'example.com')[12:]
    api('appearance',dict(title='Custom block heading',message='A custom explanation.'))
    status,_,page=request('/',host='blocked-probe.'+HOST)
    assert status==200 and b'Custom block heading' in page and b'Protected by' not in page
    print('Docker integration passed: native resolver, TLS dashboard login, profile isolation, site exceptions, YouTube A/AAAA/HTTPS handling, device pause and private-CA HTTPS block pages.')

if __name__=='__main__': globals()[sys.argv[1]]()
