#!/usr/bin/env python3
"""Token-selected DNS policies; private state survives repository updates."""
import ipaddress
import fcntl
import json
import mmap
import os
import re
import threading
import time
import urllib.parse
import urllib.request
import hub
import devices

CATEGORIES = ('ads_malware', 'adult', 'gambling')
LABELS = {'ads_malware': 'Ads / malware', 'adult': 'Adult content', 'gambling': 'Gambling'}
_cache = {}
_cache_lock = threading.Lock()

class DomainFile:
    """Binary search in sorted, validated list files without retaining Python sets."""
    def __init__(self, path):
        with path.open('rb') as source:
            self.data = mmap.mmap(source.fileno(), 0, access=mmap.ACCESS_READ)
    def __contains__(self, domain):
        target = domain.encode('ascii')
        low, high = 0, len(self.data)
        while low < high:
            middle = (low + high) // 2
            start = self.data.rfind(b'\n', low, middle) + 1
            if start < low:
                start = low
            end = self.data.find(b'\n', middle)
            if end < 0:
                end = len(self.data)
            value = self.data[start:end]
            if value == target:
                return True
            if value < target:
                low = end + 1
            else:
                high = start
        return False
    def close(self):
        self.data.close()


def normalize_site(value):
    value = value.strip()
    parsed = urllib.parse.urlsplit(value if '://' in value else '//' + value)
    if parsed.scheme and parsed.scheme not in ('http', 'https'):
        raise ValueError('Enter a domain or an http/https website URL.')
    if parsed.username or parsed.password:
        raise ValueError('Do not include credentials in a website URL.')
    host = (parsed.hostname or '').rstrip('.').lower()
    try:
        host = host.encode('idna').decode('ascii')
        ipaddress.ip_address(host)
    except UnicodeError as error:
        raise ValueError('Invalid domain.') from error
    except ValueError:
        pass
    else:
        raise ValueError('DNS site rules require a domain, not an IP address.')
    if len(host) > 253 or '.' not in host or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?', label) for label in host.split('.')):
        raise ValueError('Enter a valid domain, for example example.com.')
    return host


def atomic(path, data):
    temporary = path.with_suffix('.tmp')
    hub.write(temporary, json.dumps(data, indent=2))
    os.replace(temporary, path)


def initial():
    policy = hub.load(hub.SOURCE / 'policy.json')
    def item(name, categories):
        return dict(name=name, categories=categories, blocked_sites=[], allowed_sites=[])
    return {'revision': 1, 'profiles': {
        'default': item('Default (existing devices)', list(policy['enabled_categories'])),
        'adults': item('Adults', ['ads_malware']),
        'kids': item('Kids', list(CATEGORIES))}}


def ensure():
    with devices.locked():
        path = hub.ROOT / 'control/profiles.json'
        if not path.exists():
            atomic(path, initial())
        return hub.load(path)


def snapshot():
    path = hub.ROOT / 'control/profiles.json'
    with devices.locked():
        return hub.load(path) if path.exists() else None


def validate(data):
    if not isinstance(data, dict) or set(data) != {'revision', 'profiles'} or type(data['revision']) is not int or data['revision'] <= 0:
        raise ValueError('Invalid profile policy.')
    items = data['profiles']
    if not isinstance(items, dict) or not 1 <= len(items) <= 100 or 'default' not in items:
        raise ValueError('Invalid profiles.')
    for key, item in items.items():
        if not isinstance(key, str) or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', key):
            raise ValueError('Invalid profile id.')
        if not isinstance(item, dict) or set(item) != {'name', 'categories', 'blocked_sites', 'allowed_sites'}:
            raise ValueError('Invalid profile fields.')
        if not isinstance(item['name'], str) or not 1 <= len(item['name']) <= 80:
            raise ValueError('Invalid profile name.')
        for field in ('categories', 'blocked_sites', 'allowed_sites'):
            values = item[field]
            if not isinstance(values, list) or len(values) > 5000 or any(not isinstance(x, str) for x in values) or len(set(values)) != len(values):
                raise ValueError('Invalid profile rules.')
        if any(x not in CATEGORIES for x in item['categories']):
            raise ValueError('Unknown category.')
        for domain in item['blocked_sites'] + item['allowed_sites']:
            if normalize_site(domain) != domain:
                raise ValueError('Invalid site rule.')
    return data


def merge(incoming):
    validate(incoming)
    with devices.locked():
        path = hub.ROOT / 'control/profiles.json'
        current = hub.load(path) if path.exists() else None
        rank = lambda x: (x['revision'], json.dumps(x, sort_keys=True))
        if current is None or rank(incoming) > rank(current):
            atomic(path, incoming)
            return incoming
        return current


def edit(change):
    ensure()
    with devices.locked():
        path = hub.ROOT / 'control/profiles.json'
        data = hub.load(path)
        change(data['profiles'])
        data['revision'] = max(time.time_ns(), data['revision'] + 1)
        validate(data)
        atomic(path, data)
    devices.sync_message()


def choose(all_profiles=False):
    items = ensure()['profiles']
    keys = list(items)
    for number, key in enumerate(keys, 1):
        item = items[key]
        labels = ', '.join(LABELS[c] for c in item['categories']) or 'none'
        print(f"{number}. {item['name']} (blocked categories: {labels})")
    if all_profiles:
        print('0. All profiles')
    answer = hub.ask('Profile number or name')
    if all_profiles and answer.casefold() in ('0', 'all', 'both'):
        return keys
    if answer.isdecimal() and 1 <= int(answer) <= len(keys):
        return [keys[int(answer) - 1]]
    matches = [key for key in keys if answer.casefold() in (key.casefold(), items[key]['name'].casefold())]
    if len(matches) != 1:
        raise ValueError('Profile not found or ambiguous.')
    return matches


def site_rule(blocked):
    domain = normalize_site(hub.ask('Website URL or domain'))
    print('Rule covers ' + domain + ' and its subdomains. DNS cannot filter individual URL paths.')
    keys = choose(all_profiles=True)
    def change(items):
        for key in keys:
            item = items[key]
            target, opposite = ('blocked_sites', 'allowed_sites') if blocked else ('allowed_sites', 'blocked_sites')
            # An allow rule is an explicit exception even to a category block.
            item[opposite] = [x for x in item[opposite] if x != domain]
            item[target] = sorted(set(item[target]) | {domain})
    edit(change)
    print(domain + (': blocked on selected profiles.' if blocked else ': allowed on selected profiles.'))
    print('Devices can retain cached DNS answers for their remaining TTL; existing connections can continue.')


def manage():
    print('1 Show profiles   2 Create profile   3 Set categories   4 Move device   5 Remove site rule')
    command = hub.ask('Action number')
    if command == '1':
        data = ensure()['profiles']
        registry = devices.snapshot()
        for key, item in data.items():
            members = [d['name'] for d in registry.values() if d.get('profile', 'default') == key]
            print(item['name'] + ': ' + (', '.join(members) or 'no devices'))
            print('  Categories: ' + (', '.join(item['categories']) or 'none'))
            print('  Block: ' + (', '.join(item['blocked_sites']) or 'none'))
            print('  Allow: ' + (', '.join(item['allowed_sites']) or 'none'))
    elif command == '2':
        name = hub.ask('Profile name')
        key = re.sub(r'[^a-z0-9_-]+', '-', name.lower()).strip('-_')[:64]
        if not 1 <= len(name) <= 80 or not re.fullmatch(r'[a-z0-9][a-z0-9_-]{0,63}', key):
            raise ValueError('Use a profile name containing letters or numbers, at most 80 characters.')
        selected = category_selection()
        def change(items):
            if key in items:
                raise ValueError('That profile already exists.')
            items[key] = dict(name=name, categories=selected, blocked_sites=[], allowed_sites=[])
        edit(change)
    elif command == '3':
        key = choose()[0]
        selected = category_selection()
        edit(lambda items: items[key].update(categories=selected))
    elif command == '4':
        device = devices.choose_device()
        key = choose()[0]
        with devices.locked():
            data = devices.registry_unlocked()
            item = data[device['id']]
            item['profile'] = key
            item['revision'] = max(time.time_ns(), item['revision'] + 1)
            devices.save(data)
        devices.sync_message()
        print('Device moved. Its existing iPhone configuration remains valid.')
    elif command == '5':
        domain = normalize_site(hub.ask('Site rule to remove'))
        keys = choose(all_profiles=True)
        def change(items):
            for key in keys:
                for field in ('blocked_sites', 'allowed_sites'):
                    items[key][field] = [x for x in items[key][field] if x != domain]
        edit(change)
    else:
        raise ValueError('Choose an action from 1 to 5.')


def category_selection():
    print('Choose categories to BLOCK. 1 Ads / malware   2 Adult content   3 Gambling')
    answer = hub.ask('Numbers separated by commas, or none')
    if answer.casefold() == 'none':
        return []
    choices = [x.strip() for x in answer.split(',')]
    if not choices or any(x not in ('1', '2', '3') for x in choices):
        raise ValueError('Enter category numbers, for example 1,2,3, or none.')
    return [c for i, c in enumerate(CATEGORIES, 1) if str(i) in choices]


def parse_list(text):
    result = set()
    for line in text.splitlines():
        domain = line.strip().lower()
        if not domain or domain.startswith('#'):
            continue
        if len(domain) > 253 or '.' not in domain or any(not re.fullmatch(r'[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?', x) for x in domain.split('.')):
            raise ValueError('Invalid category list content; previous list retained.')
        result.add(domain)
    if len(result) < 100:
        raise ValueError('Category list is unexpectedly empty or small; previous list retained.')
    return result


def refresh_lists(force=False):
    ensure()
    directory = hub.ROOT / 'control/category-lists'
    directory.mkdir(mode=0o700, parents=True, exist_ok=True)
    # Host updates and the gateway refresher share this lock, without holding
    # the device/policy lock while downloading large lists.
    with (directory / 'download.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        _refresh_lists(directory, force)

def _refresh_lists(directory, force):
    urls = hub.load(hub.SOURCE / 'policy.json')['blocklists']
    for category in CATEGORIES:
        path = directory / (category + '.txt')
        if not force and path.exists() and time.time() - path.stat().st_mtime < 86400:
            continue
        try:
            sources = [urls[category]]
            prefix = 'https://raw.githubusercontent.com/hagezi/dns-blocklists/main/'
            if sources[0].startswith(prefix):
                sources.append('https://cdn.jsdelivr.net/gh/hagezi/dns-blocklists@main/' + sources[0][len(prefix):])
            for index, url in enumerate(sources):
                print(category + ': downloading from ' + ('primary source' if index == 0 else 'mirror') + ' (45-second transfer deadline).', flush=True)
                try:
                    domains = parse_list(download(url).decode('utf-8'))
                    break
                except (OSError, ValueError, UnicodeError):
                    if index == len(sources) - 1:
                        raise
                    print(category + ': primary failed; trying mirror.', flush=True)
            temporary = path.with_suffix('.tmp')
            hub.write(temporary, '\n'.join(sorted(domains)) + '\n')
            os.replace(temporary, path)
            del domains
            print(category + ': downloaded and validated category list.', flush=True)
        except (OSError, ValueError, UnicodeError) as error:
            if not path.exists():
                raise RuntimeError('No usable ' + category + ' list: ' + str(error)) from error
            parse_list(path.read_text())
            print(category + ': download failed; retaining last known good list: ' + str(error))

def download(url):
    deadline = time.monotonic() + 45
    with urllib.request.urlopen(url, timeout=10) as response:
        if response.status != 200:
            raise ValueError('Category download failed.')
        chunks, size = [], 0
        while True:
            if time.monotonic() > deadline:
                raise TimeoutError('Category download exceeded total time limit.')
            chunk = response.read(65536)
            if not chunk:
                return b''.join(chunks)
            size += len(chunk)
            if size > 50_000_000:
                raise ValueError('Category list is too large.')
            chunks.append(chunk)


def ancestors(domain):
    labels = domain.lower().rstrip('.').split('.')
    return ['.'.join(labels[i:]) for i in range(len(labels))]


def specificity(domain, rules):
    return max((len(x.split('.')) for x in ancestors(domain) if x in rules), default=0)


def blocked(domain, profile):
    # Longest explicit domain wins. An exact allow wins a tie with a block.
    allow = specificity(domain, profile['allowed_sites'])
    deny = specificity(domain, profile['blocked_sites'])
    if allow or deny:
        return deny > allow
    names = ancestors(domain)
    for category in profile['categories']:
        path = hub.ROOT / 'control/category-lists' / (category + '.txt')
        stat = path.stat()  # Missing enabled lists fail closed, never bypass filtering.
        signature = (stat.st_mtime_ns, stat.st_size, stat.st_ino)
        cache_key = str(path)
        with _cache_lock:
            current = _cache.get(cache_key)
            if current is None or current[0] != signature:
                if current is not None:
                    current[1].close()
                current = (signature, DomainFile(path))
                _cache[cache_key] = current
            if any(x in current[1] for x in names):
                return True
    return False


def for_device(device):
    data = snapshot()
    if data is None:
        raise ValueError('DNS profile policy is unavailable.')
    key = device.get('profile', 'default') if device else 'default'
    if key not in data['profiles']:
        raise ValueError('Assigned DNS profile is unavailable.')
    return data['profiles'][key]
