#!/usr/bin/env python3
"""Two-node private DNS installer. All secrets stay outside the git checkout."""
import argparse
import base64
import ipaddress
import http.client
import sys
import json
import os
import re
import getpass
import fcntl
from pathlib import Path
import plistlib
import secrets
import socket
import struct
import subprocess
import tarfile
import time
import urllib.parse
import urllib.request
import uuid

ROOT = Path(os.environ.get('DNS_HUB_ROOT', '/opt/dns-control-hub'))
SOURCE = Path(__file__).resolve().parent
HOST = 'dns.private.invalid'  # Bootstrap only; production hostname comes from setup.
ALBANIA_IP = '45.88.89.23'
ENGINE = 'unbound'

def run(*args):
    subprocess.run(args, check=True, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)

def write(path, content, mode=0o600):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(content)
    path.chmod(mode)

def load(path):
    return json.loads(Path(path).read_text())

def ask(prompt):
    # Text update mode requires seeking, which a terminal cannot support.
    # Separate streams also keep prompts working when stdin is a curl pipe.
    with open('/dev/tty', 'w') as output:
        output.write(prompt + ': ')
        output.flush()
    with open('/dev/tty', 'r') as input_stream:
        answer = input_stream.readline()
    if not answer:
        raise RuntimeError('Terminal closed before an answer was entered.')
    return answer.strip()

def ipv4(value):
    addr = ipaddress.IPv4Address(value)
    if not addr.is_global:
        raise ValueError('Use a public IPv4 address.')
    return str(addr)

def payload(kind, name, **extra):
    return dict(PayloadType=kind, PayloadVersion=1, PayloadIdentifier='private.dns.' + str(uuid.uuid4()),
                PayloadUUID=str(uuid.uuid4()), PayloadDisplayName=name, **extra)

def profile(settings, certificate, device=None):
    device = device or {'name': 'Private DNS', 'token': settings['endpoint_key'], 'type': 'iOS'}
    dns = payload('com.apple.dnsSettings.managed', device['name'] + ' DNS',
                  DNSSettings={'DNSProtocol': 'HTTPS', 'ServerAddresses': settings['dns_ips'],
                  'ServerURL': 'https://' + settings['hostname'] + '/dns/' + device['token'] + '/dns-query'},
                  OnDemandRules=[{'Action': 'Connect'}])
    ca = payload('com.apple.security.root', 'Private block-page CA', PayloadContent=certificate)
    return plistlib.dumps(payload('Configuration', device['name'] + ' Private DNS', PayloadContent=[ca, dns],
                                 PayloadDescription='Encrypted DNS and HTTPS block pages for ' + device['type']))

def hostname(value):
    value = value.strip().lower().rstrip('.')
    if len(value) > 253 or '.' not in value or not re.fullmatch(r'[a-z0-9.-]+', value):
        raise ValueError('Enter a DNS hostname, e.g. dns.example.com.')
    if any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in value.split('.')):
        raise ValueError('Invalid DNS hostname.')
    return value


def setup():
    os.umask(0o077)
    if (ROOT / 'node.json').exists():
        print('Existing installation retained. Applying repository policy.')
        return
    for port in (80, 443, 5380, 18053, 15353):
        with socket.socket() as sock:
            try:
                sock.bind(('0.0.0.0', port))
            except PermissionError:
                raise RuntimeError('Run the installer as root.')
            except OSError:
                raise RuntimeError(f'Port {port} is already in use. Use a fresh VPS.')
    bundle = ask('Pairing bundle path for second VPS, or Enter for first VPS')
    shared = ROOT / 'shared'
    shared.mkdir(parents=True, exist_ok=True)
    if bundle:
        # No arbitrary paths, links, or executables may be extracted.
        allowed = {'settings.json', 'ca.key', 'ca.crt', 'ca.der', 'ca.p12', 'tls/key.pem', 'tls/fullchain.pem'}
        with tarfile.open(bundle, 'r:gz') as archive:
            members = archive.getmembers()
            if {m.name for m in members} != allowed or any(not m.isfile() for m in members):
                raise ValueError('Invalid pairing bundle.')
            for member in members:
                data = archive.extractfile(member).read()
                destination = ROOT / member.name if member.name.startswith('tls/') else shared / member.name
                destination.parent.mkdir(exist_ok=True)
                destination.write_bytes(data)
                destination.chmod(0o600)
        settings = load(shared / 'settings.json')
        settings['dns_ips'] = [ipv4(x) for x in settings['dns_ips']]
        settings['proxy_ip'] = ALBANIA_IP
        settings['hostname'] = hostname(settings['hostname'])
        if len(settings['dns_ips']) not in (1, 2) or len(settings['endpoint_key']) != 64 or not all(c in '0123456789abcdef' for c in settings['endpoint_key']):
            raise ValueError('Invalid shared settings.')
    else:
        ips = [ipv4(ask('First DNS VPS public IPv4'))]
        second_ip = ask('Second DNS VPS public IPv4, or Enter to use one VPS')
        if second_ip:
            ips.append(ipv4(second_ip))
        if len(ips) == 2 and ips[0] == ips[1]:
            raise ValueError('DNS VPS IP addresses must differ.')
        settings = {'dns_ips': ips, 'proxy_ip': ALBANIA_IP,
                    'hostname': hostname(ask('DNS hostname pointing to the FIRST DNS VPS (any provider)')),
                    'certificate_mode': 'http',
                    'acme_email': ask('Certificate account email (stored privately on this VPS)'),
                    'management_key': secrets.token_hex(32), 'endpoint_key': secrets.token_hex(32)}
        write(shared / 'settings.json', json.dumps(settings, indent=2))
        run('openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256', '-days', '3650',
            '-subj', '/CN=Private DNS Blockpage CA', '-addext', 'basicConstraints=critical,CA:TRUE',
            '-addext', 'keyUsage=critical,keyCertSign,cRLSign', '-keyout', str(shared / 'ca.key'), '-out', str(shared / 'ca.crt'))
        run('openssl', 'x509', '-in', str(shared / 'ca.crt'), '-outform', 'DER', '-out', str(shared / 'ca.der'))
        run('openssl', 'pkcs12', '-export', '-inkey', str(shared / 'ca.key'), '-in', str(shared / 'ca.crt'),
            '-out', str(shared / 'ca.p12'), '-passout', 'pass:')
    node_ip = ipv4(ask('This DNS VPS public IPv4'))
    if node_ip not in settings['dns_ips']:
        raise ValueError('This VPS must be one of the configured DNS IPs.')
    write(ROOT / 'node.json', json.dumps({'public_ip': node_ip, 'admin_password': secrets.token_urlsafe(32)}))
    exports = ROOT / 'exports'
    exports.mkdir(exist_ok=True)
    (ROOT / 'control').mkdir(exist_ok=True)
    print('Shared identity created. Pairing bundle is exported after the public certificate is issued.')

def pairing_bundle():
    exports = ROOT / 'exports'
    exports.mkdir(exist_ok=True)
    with tarfile.open(exports / 'dns-pairing.tar.gz', 'w:gz') as archive:
        for name in ('settings.json', 'ca.key', 'ca.crt', 'ca.der', 'ca.p12'):
            archive.add(ROOT / 'shared' / name, arcname=name)
        for name in ('key.pem', 'fullchain.pem'):
            archive.add(ROOT / 'tls' / name, arcname='tls/' + name)
    print('Private pairing bundle updated.')


def render():
    import stack
    stack.render()

def certificates():
    """Configured hostname: HTTP-01 on VPS 1; VPS 2 imports the same TLS identity."""
    import threading
    from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
    settings = load(ROOT / 'shared/settings.json')
    node = load(ROOT / 'node.json')
    tls = ROOT / 'tls'
    tls.mkdir(exist_ok=True)
    if (tls / 'fullchain.pem').exists() and (tls / 'key.pem').exists():
        pairing_bundle()
        return
    if node['public_ip'] != settings['dns_ips'][0]:
        raise RuntimeError('Second VPS requires a pairing bundle containing the first VPS public certificate.')
    email = settings['acme_email']
    if not re.fullmatch(r'[^\s@]+@[^\s@]+\.[^\s@]+', email):
        raise ValueError('Enter a valid certificate email address.')
    acme = '/root/.acme.sh/acme.sh'
    if not Path(acme).exists():
        raise RuntimeError('acme.sh has not been installed.')
    webroot = ROOT / 'webroot'
    webroot.mkdir(exist_ok=True)
    class ChallengeHandler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=str(webroot), **kwargs)
        def log_message(self, *args): pass
        def do_GET(self):
            if not self.path.startswith('/.well-known/acme-challenge/'):
                self.send_error(404)
                return
            super().do_GET()
    subprocess.run([acme, '--register-account', '--server', 'zerossl', '-m', email], check=True)
    # Bootstrap HTTP service serves only ACME challenge files. Later renewal uses Nginx.
    server = ThreadingHTTPServer(('0.0.0.0', 80), ChallengeHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        subprocess.run([acme, '--issue', '--server', 'zerossl', '--webroot', str(webroot),
                        '-d', settings['hostname'], '--keylength', 'ec-256'], check=True)
    finally:
        server.shutdown()
        server.server_close()
    subprocess.run([acme, '--install-cert', '-d', settings['hostname'], '--ecc',
                    '--key-file', str(tls / 'key.pem'), '--fullchain-file', str(tls / 'fullchain.pem'),
                    '--reloadcmd', str(SOURCE / 'reload-tls.sh')], check=True)
    pairing_bundle()



def console():
    import stack
    stack.console()

def apply():
    import stack
    stack.apply()

def blocking_probe(settings):
    # RFC 6761 .test/.invalid are authoritative local zones in Technitium,
    # so their NXDOMAIN answers precede recursive blocked-zone policy.
    return 'blocked-probe.' + settings['hostname']

def dns_query(name):
    qname = b''.join(bytes([len(s)]) + s.encode() for s in name.split('.')) + b'\0'
    return struct.pack('!6H', 4567, 0x100, 1, 0, 0, 0) + qname + struct.pack('!2H', 1, 1)

def check():
    import stack
    stack.check()

def check_profile_filters(shared):
    import profiles
    policy = profiles.for_device(None)
    ip = ipaddress.IPv4Address(load(ROOT / 'node.json')['public_ip']).packed
    for category in policy['categories']:
        path = ROOT / 'control/category-lists' / (category + '.txt')
        names = profiles.parse_list(path.read_text())
        name = next((name for name in names if profiles.blocked(name, policy)), None)
        if name is None:
            continue  # All category members explicitly allowed in Default.
        query = base64.urlsafe_b64encode(dns_query(name)).decode().rstrip('=')
        answer = subprocess.check_output(['curl', '--fail', '--silent', '--show-error', '--max-time', '20',
            '--connect-to', shared['hostname'] + ':443:127.0.0.1:443',
            'https://' + shared['hostname'] + '/dns/' + shared['endpoint_key'] + '/dns-query?dns=' + query])
        if len(answer) < 12 or struct.unpack('!6H', answer[:12])[3] != 1 or not answer.endswith(ip):
            raise RuntimeError('Live profile category check failed: ' + category)
    print('Profile gateway and enabled Default categories checked over HTTPS.')

def refresh_youtube():
    # Validate the maintained service-domain catalogue before touching working policy.
    url = 'https://raw.githubusercontent.com/AdguardTeam/HostlistsRegistry/main/services/youtube.yml'
    with urllib.request.urlopen(url, timeout=30) as response:
        text = response.read(512000).decode()
    domains = sorted(set(re.findall(r"^\s*- ['\"]\|\|([a-zA-Z0-9.-]+)\^['\"]\s*$", text, re.M)))
    domains = [d.lower() for d in domains if '.' in d]
    if len(domains) < 5 or len(domains) > 1000 or 'googlevideo.com' not in domains or 'youtube.com' not in domains:
        raise RuntimeError('Unexpected YouTube catalogue; keeping last known good rules.')
    # Do not accidentally capture all of Google or a public suffix.
    allowed = ('youtube', 'youtu', 'yt.', 'ytimg', 'googlevideo', 'ggpht', 'withyoutube')
    if any(not any(word in d for word in allowed) for d in domains):
        raise RuntimeError('Unrecognised domain in catalogue; review before applying.')
    write(ROOT / 'youtube-domains.json', json.dumps(domains))
    apply()
    print('YouTube catalogue refreshed. A/AAAA/HTTPS handling remains a DNS override, not an IP inventory.')

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('command', choices=['setup', 'render', 'apply', 'check', 'certificates', 'refresh-youtube', 'console'])
    args = parser.parse_args()
    if args.command == 'render' and os.geteuid() == 0:
        import devices
        import profiles
        # Prepare filtering before the updater restarts the working gateway.
        # This also repairs older update-live wrappers without replacing them.
        profiles.refresh_lists()
        devices.helpers()
    globals()[args.command.replace('-', '_')]()
