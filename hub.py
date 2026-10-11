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
IMAGE = 'technitium/dns-server:15.6.1'

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
    import profiles
    profiles.ensure()
    settings, node = load(ROOT / 'shared/settings.json'), load(ROOT / 'node.json')
    host = settings['hostname']
    write(ROOT / 'admin-password', node['admin_password'])
    (ROOT / 'data').mkdir(exist_ok=True)
    (ROOT / 'control').mkdir(exist_ok=True)
    (ROOT / 'webroot').mkdir(exist_ok=True)
    (ROOT / 'blockpage').mkdir(exist_ok=True)
    write(ROOT / 'blockpage/index.html', (SOURCE / 'blockpage.html').read_text())
    write(ROOT / 'compose.yaml', f'''services:
  dns:
    image: {IMAGE}
    restart: unless-stopped
    ports:
      - "127.0.0.1:5380:5380"
      - "127.0.0.1:18053:8053"
      - "127.0.0.1:15353:53/udp"
      - "127.0.0.1:15353:53/tcp"
    volumes:
      - ./data:/etc/dns
      - ./shared/ca.p12:/run/dns-hub/ca.p12:ro
      - ./blockpage:/run/blockpage:ro
      - ./admin-password:/run/admin-password:ro
    environment:
      DNS_SERVER_ADMIN_PASSWORD_FILE: /run/admin-password
      DNS_SERVER_DOMAIN: {host}
      DNS_SERVER_RECURSION: AllowOnlyForPrivateNetworks
  api:
    image: python:3.12-alpine
    restart: unless-stopped
    command: ["python3", "/app/gateway.py"]
    volumes:
      - ./source:/app:ro
      - ./control:/state/control
      - ./shared/settings.json:/state/shared/settings.json:ro
      - ./shared/ca.der:/state/shared/ca.der:ro
      - ./node.json:/state/node.json:ro
    environment:
      DNS_HUB_ROOT: /state
      DNS_HUB_UPSTREAM: http://dns:8053/dns-query
  doh:
    image: nginx:1.28-alpine
    restart: unless-stopped
    ports:
      - "80:80"
    volumes:
      - ./webroot:/run/acme:ro
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./tls:/run/tls:ro
  gateway:
    image: haproxy:3.2-alpine
    restart: unless-stopped
    ports:
      - "443:443"
    volumes:
      - ./haproxy.cfg:/usr/local/etc/haproxy/haproxy.cfg:ro
    depends_on: [dns, doh, api]
''')
    console_locations = "location / { return 404; }"
    if node.get('console_ready'):
        console_proxy = """set $console dns:5380;
      proxy_pass http://$console;
      proxy_set_header Host $host;
      proxy_set_header X-Forwarded-Proto https;
      proxy_set_header X-Forwarded-For $remote_addr;
      proxy_read_timeout 180s;
      add_header X-Content-Type-Options nosniff always;
      add_header X-Frame-Options DENY always;"""
        console_locations = """location = /api/user/login {
      limit_req zone=console_login burst=5 nodelay;
      limit_req_status 429;
      """ + console_proxy + """
    }
    location / {
      client_max_body_size 64m;
      """ + console_proxy + """
    }"""
    write(ROOT / 'nginx.conf', '''events {}
http {
  access_log off;
  server_tokens off;
  limit_req_zone $binary_remote_addr zone=dns:10m rate=100r/s;
  limit_req_zone $binary_remote_addr zone=console_login:10m rate=5r/m;
  resolver 127.0.0.11 valid=10s;
  server {
    listen 80;
    server_name HOSTNAME;
    location ^~ /.well-known/acme-challenge/ { root /run/acme; }
    location / { return 301 https://$host$request_uri; }
  }
  server {
    listen 80 default_server;
    server_name _;
    location / {
      set $block dns:80;
      proxy_pass http://$block;
      proxy_set_header Host $host;
    }
  }
  server {
    listen 443 ssl;
    server_name HOSTNAME;
    ssl_certificate /run/tls/fullchain.pem;
    ssl_certificate_key /run/tls/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 2m;
    location ~ ^/(dns/|profiles/|control(?:/(?:certificate|policy))?$) {
      limit_req zone=dns burst=200 nodelay;
      set $backend api:8080;
      proxy_pass http://$backend;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_read_timeout 15s;
    }
    CONSOLE_LOCATIONS
  }
}
'''.replace('HOSTNAME', host).replace('CONSOLE_LOCATIONS', console_locations))
    write(ROOT / 'haproxy.cfg', '''global
  maxconn 4096
defaults
  mode tcp
  timeout connect 5s
  timeout client 30s
  timeout server 30s
resolvers docker
  nameserver local 127.0.0.11:53
  hold valid 10s
frontend tls
  bind :443
  tcp-request inspect-delay 5s
  tcp-request content accept if { req.ssl_hello_type 1 }
  use_backend doh if { req.ssl_sni -i HOSTNAME }
  default_backend blockpage
backend doh
  server doh doh:443 resolvers docker init-addr libc,none
backend blockpage
  server dns dns:443 resolvers docker init-addr libc,none
'''.replace('HOSTNAME', host), mode=0o644)

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



class API:
    def __init__(self, force_login=False):
        token_path = ROOT / 'admin-api-token'
        self.persistent = token_path.exists() and not force_login
        if self.persistent:
            self.token = token_path.read_text().strip()
            return
        self.token = None
        password = load(ROOT / 'node.json')['admin_password']
        for attempt in range(60):
            try:
                self.token = self.call('user/login', user='admin', **{'pass': password})['token']
                return
            except (OSError, RuntimeError, http.client.HTTPException):
                time.sleep(2)
        raise RuntimeError('Technitium API did not become ready.')

    def call(self, path, **params):
        req = urllib.request.Request('http://127.0.0.1:5380/api/' + path,
            data=urllib.parse.urlencode(params).encode(), method='POST')
        if self.token:
            req.add_header('Authorization', 'Bearer ' + self.token)
        with urllib.request.urlopen(req, timeout=120 if path == 'apps/downloadAndInstall' else 20) as response:
            data = json.load(response)
        if data.get('status') != 'ok':
            raise RuntimeError('Technitium API ' + path + ': ' + str(data.get('errorMessage', data.get('status'))))
        return data

    def close(self):
        if not getattr(self, 'persistent', False):
            self.call('user/logout')

def console():
    node = load(ROOT / 'node.json')
    if node.get('console_ready'):
        if not (ROOT / 'admin-api-token').exists():
            raise RuntimeError('Console automation token is missing. Restore it from your private backup.')
        return
    print('Choose your browser login password. Username: admin. Input is hidden.')
    password = getpass.getpass('New console password (at least 12 characters): ')
    confirmation = getpass.getpass('Confirm console password: ')
    if len(password) < 12 or password != confirmation:
        raise ValueError('Passwords must match and contain at least 12 characters.')
    if password == node['admin_password']:
        raise ValueError('Choose a different password.')
    api = API(force_login=True)
    try:
        token_path = ROOT / 'admin-api-token'
        if not token_path.exists():
            token = api.call('user/createToken', tokenName='DNS Control Hub automation')['token']
            write(token_path, token)
        api.call('user/changePassword', **{'pass': node['admin_password'], 'newPass': password})
        node['admin_password'] = password
        node['console_ready'] = True
        write(ROOT / 'node.json', json.dumps(node, indent=2))
        write(ROOT / 'admin-password', password)
    finally:
        try:
            api.close()
        except (OSError, RuntimeError, http.client.HTTPException):
            pass
    print('Browser password saved. Future browser password changes do not affect the automation token.')

def ensure_blockpage(api):
    # Check before each attempt: a disconnected response can still mean installation succeeded.
    for attempt in range(3):
        try:
            apps = api.call('apps/list')['response']['apps']
            if any(a['name'] == 'Block Page' for a in apps):
                return
            api.call('apps/downloadAndInstall', name='Block Page', url='https://download.technitium.com/dns/apps/BlockPageApp.zip')
            return
        except (OSError, http.client.HTTPException) as error:
            if attempt == 2:
                raise RuntimeError('Block Page installation could not be confirmed after retries. Check Technitium server logs.') from error
            print('Technitium connection interrupted; checking app installation before retrying.')
            time.sleep(2)

def apply():
    with (ROOT / 'policy.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _apply()

def _apply():
    import profiles
    profiles.refresh_lists()
    policy = load(SOURCE / 'policy.json')
    refreshed = ROOT / 'youtube-domains.json'
    if refreshed.exists():
        policy['youtube_domains'] = sorted(set(policy['youtube_domains']) | set(load(refreshed)))
    shared = load(ROOT / 'shared/settings.json')
    node = load(ROOT / 'node.json')
    api = API()
    try:
        api.call('settings/set', enableDnsOverHttp='true', dnsOverHttpPort=8053,
                 dnsReverseProxyNetworkACL='172.16.0.0/12,192.168.0.0/16,10.0.0.0/8',
                 recursion='AllowOnlyForPrivateNetworks', enableBlocking='true',
                 blockingType='CustomAddress', customBlockingAddresses=node['public_ip'],
                 blockingAnswerTtl=0,
                 blockListUrls='',
                 blockListUpdateIntervalHours=24, logQueries='false', dnssecValidation='true', dnsServerLocalEndPoints='0.0.0.0:53')
        ensure_blockpage(api)
        config = [{'name': 'private', 'enableWebServer': True, 'webServerLocalAddresses': ['0.0.0.0'],
                   'webServerUseSelfSignedTlsCertificate': False, 'webServerTlsCertificateFilePath': '/run/dns-hub/ca.p12',
                   'webServerTlsCertificatePassword': '', 'webServerEnableOnlineCertificateSigning': True,
                   'webServerRootPath': '/run/blockpage', 'serveBlockPageFromWebServerRoot': True,
                   'blockPageTitle': policy['block_page_title'], 'blockPageHeading': policy['block_page_title'],
                   'blockPageMessage': policy['block_page_message'], 'includeBlockingInfo': True}]
        api.call('apps/config/set', name='Block Page', config=json.dumps(config))
        zones = api.call('zones/list')['response']['zones']
        existing = {z['name'] for z in zones}
        previous_path = ROOT / 'managed-zones.json'
        previous = load(previous_path) if previous_path.exists() else []
        for domain in set(previous) - set(policy['youtube_domains']):
            api.call('zones/delete', zone=domain)
        for domain in policy['youtube_domains']:
            if domain not in existing:
                api.call('zones/create', zone=domain, type='Primary')
            elif domain not in previous:
                raise RuntimeError('Refusing to overwrite an unmanaged existing zone: ' + domain)
            # Persist ownership before adding records, allowing a partial installation to resume.
            managed = set(load(previous_path) if previous_path.exists() else [])
            managed.add(domain)
            write(previous_path, json.dumps(sorted(managed)))
            for name in (domain, '*.' + domain):
                api.call('zones/records/add', zone=domain, domain=name, type='A', ipAddress=ALBANIA_IP, ttl=60, overwrite='true')
            # Primary zones intentionally have no AAAA or HTTPS records; those cannot bypass the proxy.
        write(previous_path, json.dumps(policy['youtube_domains']))
        # Deterministic blocked hostname for deployment checks, independent of list download timing.
        api.call('blocked/add', domain=blocking_probe(shared))
        api.call('cache/flush')
        print('Profile filtering, YouTube redirects and block-page app configured.')
    finally:
        try:
            api.close()
        except (OSError, RuntimeError, http.client.HTTPException):
            print('API logout could not be confirmed; the session will expire automatically.', file=sys.stderr)

def blocking_probe(settings):
    # RFC 6761 .test/.invalid are authoritative local zones in Technitium,
    # so their NXDOMAIN answers precede recursive blocked-zone policy.
    return 'blocked-probe.' + settings['hostname']

def dns_query(name):
    qname = b''.join(bytes([len(s)]) + s.encode() for s in name.split('.')) + b'\0'
    return struct.pack('!6H', 4567, 0x100, 1, 0, 0, 0) + qname + struct.pack('!2H', 1, 1)

def check():
    shared = load(ROOT / 'shared/settings.json')
    query = dns_query('example.com')
    host = shared['hostname']
    key = shared['endpoint_key']
    encoded = base64.urlsafe_b64encode(query).decode().rstrip('=')
    # TLS verification is mandatory. --connect-to keeps SNI/hostname verification while testing localhost.
    output = subprocess.check_output(['curl', '--fail', '--silent', '--show-error', '--max-time', '20',
        '--retry', '10', '--retry-connrefused', '--retry-delay', '2', '--retry-max-time', '60',
        '--connect-to', host + ':443:127.0.0.1:443',
        'https://' + host + '/dns/' + key + '/dns-query?dns=' + encoded])
    header = struct.unpack('!6H', output[:12])
    if header[0] != 4567 or header[1] & 15 or not header[3]:
        raise RuntimeError('Encrypted DNS did not return a successful answer.')
    for domain, expected in [('www.youtube.com', ALBANIA_IP), (blocking_probe(shared), load(ROOT / 'node.json')['public_ip'])]:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.settimeout(10)
            sock.sendto(dns_query(domain), ('127.0.0.1', 15353))
            answer = sock.recv(4096)
        if ipaddress.IPv4Address(expected).packed not in answer[12:]:
            raise RuntimeError('DNS response check failed for ' + domain)
    probe = blocking_probe(shared)
    run('curl', '--fail', '--silent', '--show-error', '--max-time', '20', '--cacert', str(ROOT / 'shared/ca.crt'),
        '--connect-to', probe + ':443:127.0.0.1:443', 'https://' + probe + '/')
    if load(ROOT / 'node.json').get('console_ready'):
        check_console(host)
    check_profile_filters(shared)
    print('Local checks passed: verified DoH, YouTube DNS rewrite, blocked DNS response and HTTPS block page.')
    print('Still test each public IP externally and test iPhone switching with one VPS stopped.')

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

def check_console(host):
    base = ['curl', '--fail', '--silent', '--show-error', '--max-time', '20',
            '--connect-to', host + ':443:127.0.0.1:443']
    subprocess.check_output(base + ['https://' + host + '/'])
    # No bearer token: settings must remain protected by Technitium authentication.
    result = json.loads(subprocess.check_output(base + ['https://' + host + '/api/settings/get']))
    if result.get('status') not in ('invalid-token', 'error'):
        raise RuntimeError('Console authentication check failed: anonymous settings access was not rejected.')
    print('HTTPS console responds; anonymous settings access rejected.')

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
        devices.helpers()
    globals()[args.command.replace('-', '_')]()
