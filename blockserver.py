"""Serve block pages only. Never intercept or forward website traffic."""
from collections import OrderedDict
import datetime
import html
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import re
import ssl
import tempfile
import threading
from pathlib import Path
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID, ExtendedKeyUsageOID
import hub

class Certificates:
    def __init__(self):
        self.key=serialization.load_pem_private_key((hub.ROOT/'shared/ca.key').read_bytes(),None)
        self.ca=x509.load_pem_x509_certificate((hub.ROOT/'shared/ca.crt').read_bytes())
        self.cache=OrderedDict(); self.lock=threading.Lock()
    def context(self, name):
        name=hub.hostname(name)
        with self.lock:
            if name in self.cache:
                context, expiry=self.cache[name]
                if expiry>datetime.datetime.now(datetime.timezone.utc):
                    self.cache.move_to_end(name); return context
                self.cache.pop(name)
            key=ec.generate_private_key(ec.SECP256R1())
            now=datetime.datetime.now(datetime.timezone.utc)
            cert=(x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,name[:64])]))
                .issuer_name(self.ca.subject).public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now-datetime.timedelta(minutes=5)).not_valid_after(now+datetime.timedelta(days=7))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName(name)]),False)
                .add_extension(x509.BasicConstraints(ca=False,path_length=None),True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]),False)
                .sign(self.key,hashes.SHA256()))
            context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.minimum_version=ssl.TLSVersion.TLSv1_2
            with tempfile.TemporaryDirectory() as directory:
                certpath=Path(directory)/'cert.pem';keypath=Path(directory)/'key.pem'
                certpath.write_bytes(cert.public_bytes(serialization.Encoding.PEM)+self.ca.public_bytes(serialization.Encoding.PEM))
                keypath.write_bytes(key.private_bytes(serialization.Encoding.PEM,serialization.PrivateFormat.PKCS8,serialization.NoEncryption()))
                keypath.chmod(0o600); context.load_cert_chain(certpath,keypath)
            self.cache[name]=(context,now+datetime.timedelta(days=6))
            while len(self.cache)>128: self.cache.popitem(last=False)
            return context
    def sni(self, connection, name, context):
        if name is None: raise ssl.SSLError('Hostname required.')
        connection.context=self.context(name)

class Handler(BaseHTTPRequestHandler):
    def log_message(self,*args): pass
    def do_GET(self):
        content=(hub.SOURCE/'blockpage.html').read_text()
        appearance=hub.ROOT/'control/appearance.json'
        if appearance.exists():
            data=hub.load(appearance)
            content=re.sub(r'<h1>.*?</h1>',lambda _: '<h1>'+html.escape(data['title'])+'</h1>',content)
            content=content.replace('Your DNS rules have restricted access to this website.',html.escape(data['message']))
        content=content.encode()
        self.send_response(200);self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Cache-Control','no-store');self.send_header('Content-Length',str(len(content)))
        self.send_header('X-Content-Type-Options','nosniff');self.end_headers();self.wfile.write(content)

class TLSServer(ThreadingHTTPServer):
    def process_request_thread(self, request, address):
        try:
            request.settimeout(5)
            secure=self.context.wrap_socket(request,server_side=True)
            super().process_request_thread(secure,address)
        except (OSError, ssl.SSLError):
            request.close()

if __name__=='__main__':
    certificates=Certificates()
    context=certificates.context('blocked.private.invalid');context.set_servername_callback(certificates.sni)
    plain=ThreadingHTTPServer(('0.0.0.0',8081),Handler)
    secure=TLSServer(('0.0.0.0',8443),Handler);secure.context=context
    threading.Thread(target=plain.serve_forever,daemon=True).start();secure.serve_forever()
