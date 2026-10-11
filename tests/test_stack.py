import datetime
import json
from pathlib import Path
import secrets
import socket
import ssl
import struct
import tempfile
import threading
import unittest
from unittest.mock import patch
from cryptography import x509
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import admin
import blockserver
import gateway
import hub
import profiles
import stack

class StackTests(unittest.TestCase):
    def test_render_migrates_without_replacing_tokens_ca_or_profiles(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(hub,'ROOT',Path(directory)):
            root=hub.ROOT
            hub.write(root/'node.json',json.dumps(dict(public_ip='8.8.8.8',admin_password='old-password-1234',console_ready=True)))
            hub.write(root/'shared/settings.json',json.dumps(dict(hostname='dns.example.com',dns_ips=['8.8.8.8'],endpoint_key=secrets.token_hex(32))))
            hub.write(root/'shared/ca.key','original-ca-key')
            hub.write(root/'control/devices.json','{"device-token":"fixture"}')
            before=profiles.ensure()
            stack.render();stack.render()
            self.assertEqual(profiles.snapshot(),before)
            self.assertEqual((root/'shared/ca.key').read_text(),'original-ca-key')
            self.assertEqual((root/'control/devices.json').read_text(),'{"device-token":"fixture"}')
            self.assertTrue(Path((root/'control/migration-v2-backup').read_text()).exists())
            config=(root/'compose.yaml').read_text()
            self.assertNotIn('technitium',config);self.assertNotIn('5380',config)
            self.assertIn('Dockerfile.resolver',config);self.assertIn('DNS_HUB_RESOLVER: dns:5353',config)
            self.assertNotIn('ca.key:/state/shared/ca.key',config.split('  api:')[1].split('  blockpage:')[0])
            resolver=(root/'unbound.conf').read_text()
            self.assertIn('trust-anchor-file:',resolver)
            self.assertIn('local-zone: "googlevideo.com." redirect',resolver)
            self.assertIn('0 IN A 45.88.89.23',resolver)

    def test_tcp_resolver_transport_handles_split_frames(self):
        server=socket.socket();server.bind(('127.0.0.1',0));server.listen()
        packet=hub.dns_query('example.com'); answer=gateway.refuse(packet,0)
        def handle():
            connection,_=server.accept()
            with connection:
                length=struct.unpack('!H',connection.recv(2))[0]
                self.assertEqual(connection.recv(length),packet)
                for part in (struct.pack('!H',len(answer))[:1],struct.pack('!H',len(answer))[1:],answer[:5],answer[5:]): connection.sendall(part)
        thread=threading.Thread(target=handle);thread.start()
        try:
            with patch.dict('os.environ',DNS_HUB_RESOLVER=f'127.0.0.1:{server.getsockname()[1]}'):
                self.assertEqual(gateway.upstream_answer(packet),answer)
        finally: thread.join(timeout=3);server.close()

    def test_block_page_tls_uses_existing_ca_and_hostname(self):
        with tempfile.TemporaryDirectory() as directory, patch.object(hub,'ROOT',Path(directory)):
            now=datetime.datetime.now(datetime.timezone.utc)
            key=rsa.generate_private_key(65537,2048)
            name=x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,'Existing private CA')])
            ca=(x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key()).serial_number(x509.random_serial_number()).not_valid_before(now-datetime.timedelta(days=1)).not_valid_after(now+datetime.timedelta(days=365)).add_extension(x509.BasicConstraints(ca=True,path_length=None),True).sign(key,hashes.SHA256()))
            directory=hub.ROOT/'shared';directory.mkdir()
            (directory/'ca.key').write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
            (directory/'ca.crt').write_bytes(ca.public_bytes(serialization.Encoding.PEM))
            certificates=blockserver.Certificates()
            context=certificates.context('blocked.example.com');context.set_servername_callback(certificates.sni)
            server=socket.socket();server.bind(('127.0.0.1',0));server.listen()
            def handle():
                raw,_=server.accept()
                with context.wrap_socket(raw,server_side=True) as secure: secure.sendall(b'ok')
            thread=threading.Thread(target=handle);thread.start()
            try:
                client=ssl.create_default_context(cafile=str(directory/'ca.crt'))
                with client.wrap_socket(socket.create_connection(server.getsockname()),server_hostname='blocked.example.com') as secure:
                    self.assertEqual(secure.recv(2),b'ok')
                    self.assertIn(('DNS','blocked.example.com'),secure.getpeercert()['subjectAltName'])
            finally: thread.join(timeout=3);server.close()
            with self.assertRaises(ValueError): certificates.context('../invalid')
