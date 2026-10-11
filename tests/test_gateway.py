import base64
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import plistlib
import secrets
import struct
import sys
import tempfile
import threading
import unittest
from unittest.mock import patch
import urllib.error
import urllib.request

sys.path.insert(0, str(Path(__file__).parents[1]))
import hub
import devices
import gateway
import profiles

class Upstream(BaseHTTPRequestHandler):
    requests = 0
    def log_message(self, *args): pass
    def do_POST(self):
        type(self).requests += 1
        packet = self.rfile.read(int(self.headers['Content-Length']))
        ident, flags, *_ = struct.unpack('!6H', packet[:12])
        answer = struct.pack('!6H', ident, 0x8180, 1, 1, 0, 0) + packet[12:] + b'\xc0\x0c' + struct.pack('!HHIH', 1, 1, 60, 4) + bytes([93,184,216,34])
        self.send_response(200)
        self.send_header('Content-Length',str(len(answer)))
        self.end_headers()
        self.wfile.write(answer)

class GatewayTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.root_patch = patch.object(hub, 'ROOT', self.root)
        self.root_patch.start()
        self.settings = dict(hostname='dns.example.com', dns_ips=['8.8.8.8','9.9.9.9'], management_key=secrets.token_hex(32), endpoint_key=secrets.token_hex(32))
        hub.write(self.root / 'shared/settings.json', json.dumps(self.settings))
        (self.root / 'shared/ca.der').write_bytes(b'public-certificate-test-fixture')
        self.device = dict(id=secrets.token_hex(32), name='Test iPhone', slug='test-iphone', type='iOS', token=secrets.token_hex(32), download_token=secrets.token_hex(32), blocked=False, revision=10)
        devices.merge({self.device['id']:self.device})
        policy = profiles.ensure()
        policy['revision'] = 2
        policy['profiles']['default']['categories'] = []
        profiles.merge(policy)
        Upstream.requests = 0
        self.upstream = ThreadingHTTPServer(('127.0.0.1',0), Upstream)
        self.server = ThreadingHTTPServer(('127.0.0.1',0), gateway.Handler)
        self.env_patch = patch.dict('os.environ', DNS_HUB_UPSTREAM=f'http://127.0.0.1:{self.upstream.server_port}/dns-query')
        self.env_patch.start()
        for server in (self.upstream,self.server):
            threading.Thread(target=server.serve_forever,daemon=True).start()
        self.base = f'http://127.0.0.1:{self.server.server_port}'
    def tearDown(self):
        for server in (self.server,self.upstream):
            server.shutdown(); server.server_close()
        self.env_patch.stop(); self.root_patch.stop(); self.temp.cleanup()
    def request(self, path, body=None, headers=None):
        req=urllib.request.Request(self.base+path,data=body,headers=headers or {})
        return urllib.request.urlopen(req,timeout=3)
    def resolve(self, token=None, packet=None):
        packet=packet or hub.dns_query('example.com')
        token=token or self.device['token']
        with self.request('/dns/'+token+'/dns-query',packet,{'Content-Type':'application/dns-message'}) as response:
            return response.read()
    def test_block_refuses_all_record_types_and_unblock_restores_forwarding(self):
        self.assertEqual(struct.unpack('!6H',self.resolve()[:12])[3],1)
        self.device['blocked']=True;self.device['revision']=11
        devices.merge({self.device['id']:self.device})
        for qtype in (1,28,15,16,65,255):
            packet=hub.dns_query('another.example')[:-2]+struct.pack('!H',1)
            packet=packet[:-4]+struct.pack('!HH',qtype,1)
            answer=self.resolve(packet=packet)
            self.assertEqual(struct.unpack('!6H',answer[:12])[1]&15,5)
        self.assertEqual(Upstream.requests,1)
        self.device['blocked']=False;self.device['revision']=12
        devices.merge({self.device['id']:self.device})
        self.resolve()
        self.assertEqual(Upstream.requests,2)
    def test_single_node_never_attempts_peer_connection(self):
        settings = dict(self.settings, dns_ips=['8.8.8.8'])
        hub.write(self.root/'shared/settings.json', json.dumps(settings))
        hub.write(self.root/'node.json', json.dumps(dict(public_ip='8.8.8.8')))
        with patch.object(devices, 'PeerConnection') as connection:
            self.assertFalse(devices.sync_peer())
            self.assertTrue(devices.sync_message())
            connection.assert_not_called()
        self.assertEqual(struct.unpack('!6H', self.resolve()[:12])[3], 1)

    def test_unknown_device_never_gets_unfiltered_dns(self):
        answer=self.resolve(token=secrets.token_hex(32))
        self.assertEqual(struct.unpack('!6H',answer[:12])[1]&15,5)
        self.assertEqual(Upstream.requests,0)
    def test_get_doh_and_private_profile_download(self):
        encoded=base64.urlsafe_b64encode(hub.dns_query('example.com')).decode().rstrip('=')
        with self.request('/dns/'+self.device['token']+'/dns-query?dns='+encoded) as response:
            self.assertEqual(response.headers['Content-Type'],'application/dns-message')
        with self.request('/profiles/'+self.device['download_token']+'/dns.mobileconfig') as response:
            profile=plistlib.loads(response.read())
        dns=profile['PayloadContent'][1]['DNSSettings']
        self.assertEqual(dns['ServerAddresses'],self.settings['dns_ips'])
        self.assertIn(self.device['token'],dns['ServerURL'])
        self.assertNotIn(self.settings['management_key'],str(profile))
    def test_management_requires_secret_and_stale_state_cannot_unblock(self):
        self.device['blocked']=True;self.device['revision']=12
        devices.merge({self.device['id']:self.device})
        stale=dict(self.device,blocked=False,revision=11)
        body=json.dumps({stale['id']:stale}).encode()
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.request('/control',body)
        self.assertEqual(error.exception.code,403)
        with self.request('/control',body,{'Authorization':'Bearer '+self.settings['management_key']}) as response:
            state=json.load(response)
        self.assertTrue(state[self.device['id']]['blocked'])
    def test_bad_wire_packet_rejected_without_forwarding(self):
        with self.assertRaises(urllib.error.HTTPError) as error:
            self.resolve(packet=b'too short')
        self.assertEqual(error.exception.code,400)
        self.assertEqual(Upstream.requests,0)
    def test_status_change_is_device_specific(self):
        another=dict(self.device,id=secrets.token_hex(32),token=secrets.token_hex(32),download_token=secrets.token_hex(32),name='iPad',slug='ipad')
        devices.merge({another['id']:another})
        self.device['blocked']=True;self.device['revision']=11
        devices.merge({self.device['id']:self.device})
        self.assertEqual(struct.unpack('!6H',self.resolve()[:12])[1]&15,5)
        self.assertEqual(struct.unpack('!6H',self.resolve(token=another['token'])[:12])[1]&15,0)

if __name__=='__main__': unittest.main()
