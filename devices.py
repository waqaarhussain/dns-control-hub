#!/usr/bin/env python3
"""Private device registry shared by both DNS gateways and root-only helper commands."""
import base64
import fcntl
import hashlib
import http.client
import json
import os
from pathlib import Path
import re
import secrets
import socket
import ssl
import time
from contextlib import contextmanager
import hub

EXPORT_ROOT = Path('/root')

@contextmanager
def locked():
    directory = hub.ROOT / 'control'
    directory.mkdir(parents=True, exist_ok=True)
    with (directory / 'registry.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        try:
            yield
        finally:
            fcntl.flock(lock, fcntl.LOCK_UN)

def registry_unlocked():
    path = hub.ROOT / 'control/devices.json'
    return hub.load(path) if path.exists() else {}

def snapshot():
    with locked():
        return registry_unlocked()

def save(data):
    path = hub.ROOT / 'control/devices.json'
    temporary = path.with_suffix('.tmp')
    hub.write(temporary, json.dumps(data, indent=2))
    os.replace(temporary, path)

def valid_device(item):
    fields = {'id', 'name', 'slug', 'type', 'token', 'download_token', 'blocked', 'revision'}
    return (isinstance(item, dict) and set(item) in (fields, fields | {'profile'})
            and ('profile' not in item or isinstance(item['profile'], str) and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', item['profile']))
            and isinstance(item['name'], str) and 0 < len(item['name']) <= 80
            and re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', item['slug'])
            and item['type'] in ('iOS', 'iPadOS', 'tvOS', 'macOS')
            and all(isinstance(item[k], str) and re.fullmatch(r'[0-9a-f]{64}', item[k]) for k in ('id', 'token', 'download_token'))
            and type(item['blocked']) is bool and type(item['revision']) is int and item['revision'] > 0)

def merge(incoming):
    if not isinstance(incoming, dict) or len(incoming) > 500 or any(not valid_device(v) or k != v['id'] for k, v in incoming.items()):
        raise ValueError('Invalid device registry.')
    with locked():
        local = registry_unlocked()
        for key, item in incoming.items():
            current = local.get(key)
            # Deterministic convergence even if two commands run during the same clock tick.
            rank = lambda v: (v['revision'], json.dumps(v, sort_keys=True))
            if current is None or rank(item) > rank(current):
                local[key] = item
        save(local)
        return local

class PeerConnection(http.client.HTTPSConnection):
    def __init__(self, hostname, ip):
        super().__init__(hostname, timeout=6, context=ssl.create_default_context())
        self.peer_ip = ip
    def connect(self):
        raw = socket.create_connection((self.peer_ip, 443), self.timeout)
        self.sock = self._context.wrap_socket(raw, server_hostname=self.host)

def sync_peer():
    settings = hub.load(hub.ROOT / 'shared/settings.json')
    node = hub.load(hub.ROOT / 'node.json')
    ip = next((x for x in settings['dns_ips'] if x != node['public_ip']), None)
    if ip is None:
        return False
    conn = PeerConnection(settings['hostname'], ip)
    try:
        conn.request('POST', '/control', body=json.dumps(snapshot()).encode(),
            headers={'Authorization': 'Bearer ' + settings['management_key'], 'Content-Type': 'application/json'})
        response = conn.getresponse()
        data = response.read(2_000_001)
        if response.status != 200 or len(data) > 2_000_000:
            raise RuntimeError('Peer rejected device synchronisation.')
        merge(json.loads(data))
        import profiles
        policy = profiles.snapshot()
        if policy is not None:
            conn.request('POST', '/control/policy', body=json.dumps(policy).encode(),
                headers={'Authorization': 'Bearer ' + settings['management_key'], 'Content-Type': 'application/json'})
            response = conn.getresponse()
            data = response.read(2_000_001)
            if response.status != 200 or len(data) > 2_000_000:
                raise RuntimeError('Peer rejected profile policy synchronisation. Upgrade both VPSs.')
            profiles.merge(json.loads(data))
        appearance=hub.ROOT/'control/appearance.json'
        if appearance.exists():
            conn.request('POST','/control/appearance',body=appearance.read_bytes(),headers={'Authorization':'Bearer '+settings['management_key'],'Content-Type':'application/json'})
            response=conn.getresponse();data=response.read(10000)
            if response.status!=200: raise RuntimeError('Peer rejected block-page settings.')
            import admin
            admin.merge_appearance(json.loads(data))
        return True
    finally:
        conn.close()

def sync_message():
    try:
        if sync_peer():
            print('Devices and profile policy confirmed on both VPSs.')
        else:
            print('Applied on this VPS. Single-VPS mode; no failover configured.')
        return True
    except (OSError, ValueError, RuntimeError, http.client.HTTPException) as error:
        print('Applied locally. The other VPS could not be confirmed: ' + str(error))
        print('Automatic sync retries every 30 seconds. Do not assume both nodes are blocked yet.')
        return False

def new():
    # Get any device created on the other VPS before choosing a unique name.
    try:
        sync_peer()
    except (OSError, ValueError, RuntimeError, http.client.HTTPException):
        pass
    name = hub.ask('Device name')
    if not name or len(name) > 80:
        raise ValueError('Device name must be 1 to 80 characters.')
    slug = re.sub(r'[^a-z0-9_-]+', '-', name.lower()).strip('-_')[:64]
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', slug):
        raise ValueError('Use a name containing letters or numbers.')
    print('1 iOS   2 iPadOS   3 tvOS   4 macOS')
    selection = hub.ask('Device type number')
    kind = {'1': 'iOS', '2': 'iPadOS', '3': 'tvOS', '4': 'macOS'}.get(selection)
    if not kind:
        raise ValueError('Choose 1, 2, 3 or 4.')
    import profiles
    profile = profiles.choose()[0]
    create_device(name, kind, profile)
    sync_message()
    print('Files saved in ' + str(EXPORT_ROOT / slug) + '. No terminal QR code.')
    if kind == 'tvOS':
        print('Apple TV profile URL is in install-url.txt. This profile method is experimental on current tvOS; test it before relying on it.')

def create_device(name, kind, profile, export=True):
    import profiles
    if not isinstance(name,str) or not 1 <= len(name) <= 80:
        raise ValueError('Device name must be 1 to 80 characters.')
    slug=re.sub(r'[^a-z0-9_-]+','-',name.lower()).strip('-_')[:64]
    if not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}',slug) or kind not in ('iOS','iPadOS','tvOS','macOS'):
        raise ValueError('Invalid device name or type.')
    if profile not in profiles.ensure()['profiles']: raise ValueError('Unknown profile.')
    directory=EXPORT_ROOT/slug
    if export and directory.exists(): raise ValueError('Folder already exists. Choose another device name.')
    with locked():
        data=registry_unlocked()
        if len(data)>=500: raise ValueError('Device limit reached.')
        if any(d['slug']==slug for d in data.values()): raise ValueError('That device name is already registered.')
        device=dict(id=secrets.token_hex(32),name=name,slug=slug,type=kind,token=secrets.token_hex(32),download_token=secrets.token_hex(32),blocked=False,profile=profile,revision=time.time_ns())
        data[device['id']]=device;save(data)
    if export: export_device(device)
    return device

def export_pending():
    for device in snapshot().values():
        directory=EXPORT_ROOT/device['slug'];path=directory/'device.json'
        if directory.exists():
            if not path.exists() or hub.load(path).get('id')!=device['id']:
                print('Skipping unrelated folder: '+str(directory));continue
            if hub.load(path).get('revision')==device['revision']: continue
        export_device(device)

def export_device(device):
    directory = EXPORT_ROOT / device['slug']
    directory.mkdir(mode=0o700, exist_ok=True)
    settings = hub.load(hub.ROOT / 'shared/settings.json')
    config = hub.profile(settings, (hub.ROOT / 'shared/ca.der').read_bytes(), device)
    (directory / 'dns.mobileconfig').write_bytes(config)
    (directory / 'dns.mobileconfig').chmod(0o600)
    url = 'https://' + settings['hostname'] + '/profiles/' + device['download_token'] + '/dns.mobileconfig'
    hub.write(directory / 'install-url.txt', url + '\n')
    hub.write(directory / 'device.json', json.dumps(device, indent=2))
    hub.write(directory / 'README.txt', 'Install dns.mobileconfig, or use the link in install-url.txt.\nFor HTTPS block pages, trust the Private block-page CA on your device.\nThe URL is private. Never share it or upload these files to GitHub.\nApple TV: provider instructions describe General > Privacy, select Share Apple TV Analytics, press Play, then Add Profile. Menu availability varies by tvOS release and Apple does not document this DNS payload as tvOS-supported.\nBlocking refuses new DNS queries through this device token. Existing sessions and cached IP addresses can continue.\n')

def choose_device():
    try:
        sync_peer()
    except (OSError, ValueError, RuntimeError, http.client.HTTPException):
        pass
    data = snapshot()
    items = sorted(data.values(), key=lambda d: d['name'].lower())
    if not items:
        raise ValueError('No devices yet. Run new first.')
    for i, item in enumerate(items, 1):
        print(f"{i}. {item['name']} ({item['type']}) [{'BLOCKED' if item['blocked'] else 'active'}]")
    choice = hub.ask('Device number or exact name')
    if choice.isdecimal() and 1 <= int(choice) <= len(items):
        item = items[int(choice) - 1]
    else:
        matches = [x for x in items if x['name'].casefold() == choice.casefold()]
        if len(matches) != 1:
            raise ValueError('Device not found or name ambiguous.')
        item = matches[0]
    return item

def set_blocked(blocked):
    item = choose_device()
    with locked():
        data = registry_unlocked()
        current = data[item['id']]
        current['blocked'] = blocked
        current['revision'] = max(time.time_ns(), current['revision'] + 1)
        save(data)
    sync_message()
    print(item['name'] + (': all new DNS queries through its profile are refused.' if blocked else ': DNS queries enabled.'))

def helpers():
    for name in ('new', 'block', 'unblock', 'profiles', 'block-site', 'unblock-site'):
        path = Path('/usr/local/bin') / name
        if path.exists() and 'dns-control-hub' not in path.read_text():
            raise ValueError('An unrelated helper already exists: ' + str(path))
        hub.write(path, '#!/usr/bin/env bash\nset -Eeuo pipefail\nexec python3 /opt/dns-control-hub/source/devices.py ' + name + ' "$@"\n', mode=0o755)

if __name__ == '__main__':
    import sys
    if os.geteuid() != 0:
        raise SystemExit('Run this helper as root, e.g. sudo new.')
    settings = hub.load(hub.ROOT / 'shared/settings.json')
    node = hub.load(hub.ROOT / 'node.json')
    if sys.argv[1] not in ('sync', 'helpers', 'export-pending') and node['public_ip'] != settings['dns_ips'][0]:
        raise SystemExit('Run device helpers on the first DNS VPS: ' + settings['dns_ips'][0] + '. It is the device registry controller.')
    try:
        if sys.argv[1] == 'new':
            new()
        elif sys.argv[1] in ('block', 'unblock'):
            import profiles
            action = sys.argv[2] if len(sys.argv) > 2 else hub.ask('Device or site')
            if action.casefold() in ('device', '1'):
                set_blocked(sys.argv[1] == 'block')
            elif action.casefold() in ('site', '2'):
                profiles.site_rule(sys.argv[1] == 'block')
            else:
                raise ValueError('Choose device or site.')
        elif sys.argv[1] in ('block-site', 'unblock-site'):
            import profiles
            profiles.site_rule(sys.argv[1] == 'block-site')
        elif sys.argv[1] == 'profiles':
            import profiles
            profiles.manage()
        elif sys.argv[1] == 'export-pending':
            export_pending()
        elif sys.argv[1] == 'helpers':
            helpers()
        elif sys.argv[1] == 'sync':
            sync_peer()
    except (OSError, ValueError, RuntimeError) as error:
        raise SystemExit(str(error))
