"""Unbound deployment and migration. Existing Apple credentials and CA are retained."""
import base64
import datetime
import ipaddress
import json
import os
from pathlib import Path
import shutil
import socket
import struct
import subprocess
import hub
import profiles


def backup():
    marker = hub.ROOT / 'control/migration-v2-backup'
    if marker.exists(): return
    destination = hub.ROOT / 'backups' / datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%S%fZ')
    destination.mkdir(parents=True, mode=0o700)
    for name in ('node.json','compose.yaml','nginx.conf','haproxy.cfg','admin-password','admin-api-token','shared','tls','control'):
        source = hub.ROOT / name
        if not source.exists(): continue
        if source.is_dir(): shutil.copytree(source,destination/name,ignore=shutil.ignore_patterns('category-lists','*.lock'))
        else: shutil.copy2(source,destination/name)
    hub.write(marker,str(destination))
    print('Private migration backup: '+str(destination)+'. Existing resolver data remains untouched.')


def render():
    profiles.ensure()
    backup()
    settings, node = hub.load(hub.ROOT/'shared/settings.json'), hub.load(hub.ROOT/'node.json')
    host = settings['hostname']
    import admin
    if node.get('console_ready') or (hub.ROOT/'control/admin-auth.json').exists(): admin.setup()
    (hub.ROOT/'webroot').mkdir(exist_ok=True)
    config = '''server:
  interface: 0.0.0.0
  port: 5353
  access-control: 0.0.0.0/0 allow
  do-ip6: no
  username: "unbound"
  chroot: ""
  directory: "/etc/unbound"
  use-syslog: no
  logfile: ""
  verbosity: 1
  num-threads: 1
  msg-cache-size: 8m
  rrset-cache-size: 16m
  infra-cache-numhosts: 1000
  so-rcvbuf: 0
  so-sndbuf: 0
  hide-identity: yes
  hide-version: yes
  qname-minimisation: yes
  harden-dnssec-stripped: yes
  trust-anchor-file: "/usr/share/dns/root.key"
  val-permissive-mode: no
'''
    catalogue = hub.load(hub.SOURCE/'policy.json')['youtube_domains']
    extra = hub.ROOT/'youtube-domains.json'
    if extra.exists(): catalogue = sorted(set(catalogue)|set(hub.load(extra)))
    for domain in catalogue:
        hub.hostname(domain)
        config += f'  local-zone: "{domain}." redirect\n  local-data: "{domain}. 0 IN A {hub.ALBANIA_IP}"\n'
    probe = hub.blocking_probe(settings)
    config += f'  local-zone: "{probe}." redirect\n  local-data: "{probe}. 0 IN A {node["public_ip"]}"\n'
    hub.write(hub.ROOT/'unbound.conf',config,0o644)
    hub.write(hub.ROOT/'control/routing.json',json.dumps(catalogue))
    hub.write(hub.ROOT/'compose.yaml','''services:
  dns:
    build:
      context: ./source
      dockerfile: Dockerfile.resolver
    image: dns-control-hub-resolver:v2
    restart: unless-stopped
    ports:
      - "127.0.0.1:15353:5353/udp"
      - "127.0.0.1:15353:5353/tcp"
    volumes:
      - ./unbound.conf:/etc/unbound/hub.conf:ro
  api:
    build:
      context: ./source
      dockerfile: Dockerfile.app
    image: dns-control-hub-app:v2
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
      DNS_HUB_RESOLVER: dns:5353
  blockpage:
    image: dns-control-hub-app:v2
    restart: unless-stopped
    command: ["python3", "/app/blockserver.py"]
    volumes:
      - ./source:/app:ro
      - ./control:/state/control:ro
      - ./shared/ca.key:/state/shared/ca.key:ro
      - ./shared/ca.crt:/state/shared/ca.crt:ro
    environment:
      DNS_HUB_ROOT: /state
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
    depends_on: [dns, doh, api, blockpage]
''')
    hub.write(hub.ROOT/'nginx.conf','''events {}
http {
  access_log off;
  server_tokens off;
  resolver 127.0.0.11 valid=10s;
  limit_req_zone $binary_remote_addr zone=dns:10m rate=100r/s;
  limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
  server {
    listen 80;
    server_name HOSTNAME;
    location ^~ /.well-known/acme-challenge/ { root /run/acme; }
    location / { return 301 https://$host$request_uri; }
  }
  server {
    listen 80 default_server;
    server_name _;
    location / { set $block blockpage:8081; proxy_pass http://$block; proxy_set_header Host $host; }
  }
  server {
    listen 443 ssl;
    server_name HOSTNAME;
    ssl_certificate /run/tls/fullchain.pem;
    ssl_certificate_key /run/tls/key.pem;
    ssl_protocols TLSv1.2 TLSv1.3;
    client_max_body_size 2m;
    add_header X-Content-Type-Options nosniff always;
    add_header X-Frame-Options DENY always;
    add_header Referrer-Policy same-origin always;
    location = /api/console/login {
      limit_req zone=login burst=5 nodelay;
      limit_req_status 429;
      set $api api:8080;
      proxy_pass http://$api;
      proxy_set_header X-Real-IP $remote_addr;
    }
    location / {
      limit_req zone=dns burst=200 nodelay;
      set $api api:8080;
      proxy_pass http://$api;
      proxy_set_header Host $host;
      proxy_set_header X-Real-IP $remote_addr;
      proxy_read_timeout 20s;
    }
  }
}
'''.replace('HOSTNAME',host))
    hub.write(hub.ROOT/'haproxy.cfg','''global
  maxconn 1024
defaults
  mode tcp
  timeout connect 5s
  timeout client 60s
  timeout server 60s
resolvers docker
  nameserver dns 127.0.0.11:53
  resolve_retries 3
  timeout resolve 1s
  timeout retry 1s
  hold valid 10s
frontend https
  bind *:443
  tcp-request inspect-delay 5s
  tcp-request content accept if { req_ssl_hello_type 1 }
  use_backend dashboard if { req.ssl_sni -i HOSTNAME }
  default_backend blocked
backend dashboard
  server nginx doh:443 check resolvers docker init-addr libc,none
backend blocked
  server page blockpage:8443 check resolvers docker init-addr libc,none
'''.replace('HOSTNAME',host),0o644)
    print('Unbound, private DoH gateway, dashboard and block-page service configured.')


def apply():
    profiles.refresh_lists()
    render()
    print('Filtering and routing ready. No Technitium API is used.')


def console():
    import admin
    admin.setup()


def check():
    shared=hub.load(hub.ROOT/'shared/settings.json')
    host=shared['hostname']; key=shared['endpoint_key']
    for name,expected in [('example.com',None),('www.youtube.com',hub.ALBANIA_IP),(hub.blocking_probe(shared),hub.load(hub.ROOT/'node.json')['public_ip'])]:
        query=base64.urlsafe_b64encode(hub.dns_query(name)).decode().rstrip('=')
        answer=subprocess.check_output(['curl','--fail','--silent','--show-error','--max-time','20','--retry','10','--retry-connrefused','--retry-delay','2','--retry-max-time','60','--connect-to',host+':443:127.0.0.1:443','https://'+host+'/dns/'+key+'/dns-query?dns='+query])
        if len(answer)<12 or struct.unpack('!6H',answer[:12])[1]&15 or not struct.unpack('!6H',answer[:12])[3]:
            raise RuntimeError('DNS check failed for '+name)
        if expected and not answer.endswith(ipaddress.IPv4Address(expected).packed):
            raise RuntimeError('DNS routing check failed for '+name)
    base=['curl','--fail','--silent','--show-error','--max-time','20','--connect-to',host+':443:127.0.0.1:443']
    page=subprocess.check_output(base+['https://'+host+'/'])
    if b'DNS Control Hub' not in page: raise RuntimeError('Dashboard did not respond.')
    code=subprocess.check_output(['curl','--silent','--output','/dev/null','--write-out','%{http_code}','--connect-to',host+':443:127.0.0.1:443','https://'+host+'/api/console/state'])
    if code!=b'401': raise RuntimeError('Unauthenticated dashboard access was not rejected.')
    probe=hub.blocking_probe(shared)
    hub.run('curl','--fail','--silent','--show-error','--max-time','20','--cacert',str(hub.ROOT/'shared/ca.crt'),'--connect-to',probe+':443:127.0.0.1:443','https://'+probe+'/')
    hub.check_profile_filters(shared)
    print('Local checks passed: Unbound, verified DoH, YouTube redirect, authenticated dashboard and HTTPS block page.')
