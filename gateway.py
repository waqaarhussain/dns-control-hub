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

MAX_DNS = 65535

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
            settings = hub.load(hub.ROOT / 'shared/settings.json')
            if parsed.path in ('/control', '/control/certificate'):
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
            upstream = os.environ.get('DNS_HUB_UPSTREAM', 'http://dns:8053/dns-query')
            req = urllib.request.Request(upstream, data=packet, headers={'Content-Type': 'application/dns-message'})
            try:
                with urllib.request.urlopen(req, timeout=8) as response:
                    answer = response.read(MAX_DNS)
            except OSError:
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

if __name__ == '__main__':
    threading.Thread(target=sync_loop, daemon=True).start()
    ThreadingHTTPServer(('0.0.0.0', 8080), Handler).serve_forever()
