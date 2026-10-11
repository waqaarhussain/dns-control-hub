#!/usr/bin/env python3
"""DoH device gate: block decisions apply before forwarding any DNS packet."""
import base64
import hmac
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import struct
import threading
import time
import urllib.parse
import urllib.request
import devices
import hub
import profiles
import ipaddress
import socket
import admin

MAX_DNS = 65535
_routes_lock=threading.Lock()
_routes_cache=None

def upstream_answer(packet):
    address=os.environ.get('DNS_HUB_RESOLVER')
    if address:
        host,port=address.rsplit(':',1)
        with socket.create_connection((host,int(port)),timeout=8) as connection:
            connection.sendall(struct.pack('!H',len(packet))+packet)
            def receive(size):
                result=b''
                while len(result)<size:
                    chunk=connection.recv(size-len(result))
                    if not chunk: raise OSError('Resolver closed the connection.')
                    result+=chunk
                return result
            size=struct.unpack('!H',receive(2))[0]
            if not 12<=size<=MAX_DNS: raise ValueError('Invalid resolver answer size.')
            return receive(size)
    upstream=os.environ.get('DNS_HUB_UPSTREAM','http://dns:8053/dns-query')
    request=urllib.request.Request(upstream,data=packet,headers={'Content-Type':'application/dns-message'})
    with urllib.request.urlopen(request,timeout=8) as response:
        return response.read(MAX_DNS)

def route_matches(domain):
    global _routes_cache
    path=hub.ROOT/'control/routing.json'
    generated=path.exists()
    if not generated: path=hub.SOURCE/'policy.json'
    stat=path.stat();signature=(str(path),stat.st_mtime_ns,stat.st_size,stat.st_ino)
    with _routes_lock:
        if _routes_cache is None or _routes_cache[0]!=signature:
            value=hub.load(path)
            _routes_cache=(signature,frozenset(value if generated else value['youtube_domains']))
        routes=_routes_cache[1]
    return any(name in routes for name in profiles.ancestors(domain))

def read_name(packet, offset):
    labels, seen, end = [], set(), None
    while True:
        if offset >= len(packet) or offset in seen or len(seen) > 128:
            raise ValueError('Invalid DNS name compression.')
        seen.add(offset)
        length = packet[offset]
        if length & 0xc0 == 0xc0:
            if offset + 1 >= len(packet):
                raise ValueError('Truncated DNS pointer.')
            pointer = ((length & 0x3f) << 8) | packet[offset + 1]
            if pointer >= offset:
                raise ValueError('Invalid forward DNS pointer.')
            if end is None:
                end = offset + 2
            offset = pointer
            continue
        if length > 63 or offset + 1 + length > len(packet):
            raise ValueError('Invalid DNS label.')
        offset += 1
        if not length:
            return '.'.join(labels).lower(), end if end is not None else offset
        labels.append(packet[offset:offset + length].decode('ascii'))
        offset += length
        if sum(len(x) + 1 for x in labels) > 254:
            raise ValueError('DNS name too long.')

def question(packet):
    domain, end = read_name(packet, 12)
    if end + 4 > len(packet):
        raise ValueError('Missing DNS question.')
    qtype, qclass = struct.unpack('!HH', packet[end:end+4])
    return domain, qtype, qclass

def site_answer(packet, ip):
    _, qtype, qclass = question(packet)
    base = refuse(packet, 0)
    if qclass != 1:
        return refuse(packet)
    if qtype == 1:
        header = bytearray(base[:12])
        header[6:8] = struct.pack('!H', 1)
        return bytes(header) + base[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 0, 4) + ipaddress.IPv4Address(ip).packed
    if qtype in (28, 64, 65):
        return base  # No IPv6 address or HTTPS/SVCB hint may bypass the block page.
    return refuse(packet)

def filter_answer(answer, request, profile):
    if len(answer) < 12 or answer[:2] != request[:2]:
        raise ValueError('Invalid upstream DNS response.')
    _, flags, qd, an, ns, ar = struct.unpack('!6H', answer[:12])
    if not flags & 0x8000 or qd != 1:
        raise ValueError('Invalid upstream DNS response.')
    domain, offset = read_name(answer, 12)
    if offset + 4 > len(answer) or question(answer) != question(request):
        raise ValueError('Upstream question mismatch.')
    offset += 4
    result = bytearray(answer)
    denied = False
    redirected = False
    for index in range(an + ns + ar):
        owner, offset = read_name(answer, offset)
        if offset + 10 > len(answer):
            raise ValueError('Truncated DNS record.')
        kind, cls, ttl, length = struct.unpack('!HHIH', answer[offset:offset+10])
        data = offset + 10
        end = data + length
        if end > len(answer):
            raise ValueError('Truncated DNS record data.')
        if kind != 41:  # OPT TTL is EDNS flags, not a cache lifetime.
            result[offset+4:offset+8] = b'\0\0\0\0'
        if profile is not None and cls == 1 and index < an:
            if route_matches(owner): redirected=True
            if profiles.blocked(owner, profile):
                denied = True
            if kind in (5, 39):  # Inspect compressed CNAME and DNAME targets too.
                target, target_end = read_name(answer, data)
                if target_end != end:
                    raise ValueError('Invalid DNS alias data.')
                if profiles.blocked(target, profile):
                    denied = True
                if route_matches(target): redirected=True
        offset = end
    if offset != len(answer):
        raise ValueError('Trailing upstream DNS data.')
    return site_answer(request,hub.ALBANIA_IP) if redirected else bytes(result), denied

def refuse(packet, rcode=5):
    if len(packet) < 12:
        raise ValueError('Invalid DNS packet.')
    # Return an authenticated DNS REFUSED response, with the original question section.
    ident, flags, qd, _, _, _ = struct.unpack('!6H', packet[:12])
    if qd != 1:
        raise ValueError('Exactly one DNS question is required.')
    i = 12
    while i < len(packet):
        n = packet[i]
        i += 1
        if n == 0:
            break
        if n > 63 or i + n > len(packet):
            raise ValueError('Invalid DNS name.')
        i += n
    if i + 4 > len(packet):
        raise ValueError('Missing DNS question.')
    return struct.pack('!6H', ident, 0x8000 | (flags & 0x0100) | 0x0080 | rcode, 1, 0, 0, 0) + packet[12:i+4]

class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):
        pass  # URLs contain device credentials.
    def reply(self, code, content=b'', kind='application/octet-stream'):
        self.send_response(code)
        self.send_header('Content-Type', kind)
        self.send_header('Cache-Control', 'no-store')
        self.send_header('Content-Length', str(len(content)))
        self.end_headers()
        self.wfile.write(content)
    def body(self, limit):
        size = int(self.headers.get('Content-Length', '0'))
        if size < 0 or size > limit:
            raise ValueError('Request too large.')
        return self.rfile.read(size)
    def do_GET(self):
        self.handle_request()
    def do_POST(self):
        self.handle_request()
    def handle_request(self):
        try:
            parsed = urllib.parse.urlsplit(self.path)
            if admin.route(self,parsed): return
            settings = hub.load(hub.ROOT / 'shared/settings.json')
            if parsed.path in ('/control', '/control/certificate', '/control/policy', '/control/appearance'):
                expected = 'Bearer ' + settings['management_key']
                if self.command != 'POST' or not hmac.compare_digest(self.headers.get('Authorization', ''), expected):
                    return self.reply(403)
                if parsed.path == '/control/certificate':
                    import certificate_sync
                    bundle = json.loads(self.body(150000))
                    certificate_sync.validate(bundle, settings['hostname'])
                    # Host timer applies the staged certificate and reloads Nginx.
                    with devices.locked():
                        pending = hub.ROOT / 'control/pending-certificate.json'
                        temporary = pending.with_suffix('.tmp')
                        hub.write(temporary, json.dumps(bundle))
                        os.replace(temporary, pending)
                    return self.reply(200, b'{"staged":true}', 'application/json')
                if parsed.path == '/control/policy':
                    merged = profiles.merge(json.loads(self.body(2_000_000)))
                    return self.reply(200, json.dumps(merged).encode(), 'application/json')
                if parsed.path == '/control/appearance':
                    merged=admin.merge_appearance(json.loads(self.body(10000)))
                    return self.reply(200,json.dumps(merged).encode(),'application/json')
                merged = devices.merge(json.loads(self.body(2_000_000)))
                return self.reply(200, json.dumps(merged).encode(), 'application/json')
            download = re.fullmatch(r'/profiles/([0-9a-f]{64})/dns.mobileconfig', parsed.path)
            if download and self.command == 'GET':
                device = next((d for d in devices.snapshot().values() if hmac.compare_digest(d['download_token'], download[1])), None)
                if not device:
                    return self.reply(404)
                return self.reply(200, hub.profile(settings, (hub.ROOT / 'shared/ca.der').read_bytes(), device), 'application/x-apple-aspen-config')
            match = re.fullmatch(r'/dns/([0-9a-f]{64})/dns-query', parsed.path)
            if not match:
                return self.reply(404)
            if self.command == 'POST':
                if self.headers.get('Content-Type', '').split(';')[0] != 'application/dns-message':
                    return self.reply(415)
                packet = self.body(MAX_DNS)
            else:
                query = urllib.parse.parse_qs(parsed.query).get('dns', [''])[0]
                if not query or len(query) > 88000:
                    raise ValueError('Missing DNS packet.')
                packet = base64.b64decode(query + '=' * (-len(query) % 4), altchars=b'-_', validate=True)
            if not 12 <= len(packet) <= MAX_DNS:
                raise ValueError('Invalid DNS packet size.')
            refusal = refuse(packet)
            # Read device status atomically. In-flight queries may finish after a block.
            with devices.locked():
                device = next((d for d in devices.registry_unlocked().values() if hmac.compare_digest(d['token'], match[1])), None)
                health = hmac.compare_digest(match[1], settings['endpoint_key'])
                if (not device and not health) or (device and device['blocked']):
                    return self.reply(200, refusal, 'application/dns-message')
            domain, _, _ = question(packet)
            try:
                profile = profiles.for_device(device)
                if profile is not None and profiles.blocked(domain, profile):
                    ip = hub.load(hub.ROOT / 'node.json')['public_ip']
                    return self.reply(200, site_answer(packet, ip), 'application/dns-message')
                if domain == hub.blocking_probe(settings):
                    return self.reply(200, site_answer(packet, hub.load(hub.ROOT/'node.json')['public_ip']), 'application/dns-message')
                if route_matches(domain):
                    return self.reply(200, site_answer(packet, hub.ALBANIA_IP), 'application/dns-message')
            except (OSError, ValueError):
                return self.reply(200, refuse(packet, 2), 'application/dns-message')
            try:
                answer = upstream_answer(packet)
                answer, denied = filter_answer(answer, packet, profile)
                if denied:
                    answer = site_answer(packet, hub.load(hub.ROOT / 'node.json')['public_ip'])
            except (OSError, ValueError):
                answer = refuse(packet, 2)  # SERVFAIL rather than bypassing filtering.
            return self.reply(200, answer, 'application/dns-message')
        except (ValueError, KeyError, json.JSONDecodeError):
            self.reply(400)
        except OSError:
            self.reply(503)

def sync_loop():
    while True:
        try:
            devices.sync_peer()
        except Exception:
            pass  # Helper commands report peer failures; background sync retries.
        time.sleep(30)

def list_loop():
    while True:
        try:
            profiles.refresh_lists()
        except Exception as error:
            print('Category refresh failed; existing lists retained: ' + str(error), flush=True)
        time.sleep(3600)

if __name__ == '__main__':
    threading.Thread(target=sync_loop, daemon=True).start()
    threading.Thread(target=list_loop, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
