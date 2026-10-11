#!/usr/bin/env python3
"""Renewal replication uses the already trusted shared TLS hostname and management token."""
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import ssl
import subprocess
import sys
import tempfile
import devices
import hub

def validate(bundle, hostname):
    if not isinstance(bundle, dict) or set(bundle) != {'key', 'fullchain'} or any(not isinstance(v,str) or len(v)>65000 for v in bundle.values()):
        raise ValueError('Invalid certificate bundle.')
    with tempfile.TemporaryDirectory() as temp:
        key, chain = Path(temp)/'key.pem', Path(temp)/'fullchain.pem'
        key.write_text(bundle['key']); chain.write_text(bundle['fullchain'])
        key.chmod(0o600)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(str(chain), str(key))  # Also verifies key/cert correspondence.
        info = ssl._ssl._test_decode_cert(str(chain))
        if ('DNS', hostname) not in info.get('subjectAltName', []):
            raise ValueError('Certificate does not match the configured DNS hostname.')

def send():
    settings = hub.load(hub.ROOT/'shared/settings.json')
    node = hub.load(hub.ROOT/'node.json')
    if node['public_ip'] != settings['dns_ips'][0]:
        return
    bundle = {'key': (hub.ROOT/'tls/key.pem').read_text(), 'fullchain': (hub.ROOT/'tls/fullchain.pem').read_text()}
    fingerprint = hashlib.sha256(json.dumps(bundle, sort_keys=True).encode()).hexdigest()
    marker = hub.ROOT/'control/certificate-sent.sha256'
    if marker.exists() and marker.read_text() == fingerprint:
        return
    hub.pairing_bundle()
    if len(settings['dns_ips']) == 1:
        hub.write(marker, fingerprint)
        return
    conn = devices.PeerConnection(settings['hostname'], settings['dns_ips'][1])
    try:
        conn.request('POST','/control/certificate',body=json.dumps(bundle).encode(),headers={'Authorization':'Bearer '+settings['management_key'],'Content-Type':'application/json'})
        response = conn.getresponse(); response.read()
        if response.status != 200:
            raise RuntimeError('Peer rejected certificate update.')
        hub.write(marker, fingerprint)
    finally:
        conn.close()

def apply_pending():
    # Serialize host jobs, but release the registry lock before reloading services.
    control = hub.ROOT/'control'
    with (control/'certificate.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _apply_pending()

def _apply_pending():
    pending = hub.ROOT/'control/pending-certificate.json'
    path = hub.ROOT/'control/processing-certificate.json'
    with devices.locked():
        if not path.exists() and pending.exists():
            os.replace(pending, path)
    # New arrivals remain pending; failures retain this file for the next retry.
    if not path.exists():
        return
    bundle = hub.load(path)
    settings = hub.load(hub.ROOT/'shared/settings.json')
    validate(bundle,settings['hostname'])
    tls = hub.ROOT/'tls'
    # Authenticated transfer plus public chain validation before changing the live files.
    with tempfile.TemporaryDirectory() as temp:
        chain = Path(temp)/'chain.pem';chain.write_text(bundle['fullchain'])
        subprocess.run(['openssl','verify','-CApath','/etc/ssl/certs','-untrusted',str(chain),str(chain)],check=True,capture_output=True)
    hub.write(tls/'key.next.pem',bundle['key']);hub.write(tls/'fullchain.next.pem',bundle['fullchain'])
    os.replace(tls/'key.next.pem',tls/'key.pem');os.replace(tls/'fullchain.next.pem',tls/'fullchain.pem')
    subprocess.run([str(hub.SOURCE/'compose.sh'),'-f',str(hub.ROOT/'compose.yaml'),'exec','-T','doh','nginx','-t'],check=True)
    subprocess.run([str(hub.SOURCE/'compose.sh'),'-f',str(hub.ROOT/'compose.yaml'),'exec','-T','doh','nginx','-s','reload'],check=True)
    path.unlink()
    hub.pairing_bundle()
    print('Renewed public certificate installed on secondary VPS.')

if __name__ == '__main__':
    try:
        node=hub.load(hub.ROOT/'node.json');settings=hub.load(hub.ROOT/'shared/settings.json')
        if sys.argv[1]=='send' or node['public_ip']==settings['dns_ips'][0]:
            send()
        else:
            apply_pending()
    except (OSError,ValueError,RuntimeError,http.client.HTTPException,subprocess.CalledProcessError) as error:
        print('Certificate replication pending; automatic retry: '+str(error),file=sys.stderr)
        # Certificate issuance can succeed even before the secondary is installed.
        if sys.argv[1]!='send':
            raise SystemExit(1)
