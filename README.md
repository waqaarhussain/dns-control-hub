# DNS Control Hub

Private encrypted DNS with a custom family dashboard, Unbound, per-device Apple profiles, shared category/site policies, HTTPS block pages, and YouTube routing through **45.88.89.23**. The interface uses [Waqaar App UI Kit](https://github.com/waqaarhussain/waqaar-app-ui-kit), with purple/teal accents, light/dark themes, desktop navigation and mobile safe areas.

## Install or migrate from the Technitium version

Use a Ubuntu/Debian VPS. One VPS is enough to test. Point a DNS hostname's A record at the first VPS; do not add an unrelated AAAA record. Open public TCP 80 and 443. Port 53 and resolver administration are not public.

```bash
curl -fsSL https://raw.githubusercontent.com/waqaarhussain/dns-control-hub/main/install.sh | sudo bash
```

The installer asks for the DNS hostname, VPS IPs, and certificate email. Any domain provider is supported. Leave the second IP blank for a single VPS. Public certificates use pinned acme.sh with ZeroSSL HTTP validation and automatic renewal; no Certbot or provider API credentials are required.

For an existing installation, this command installs the new updater, prepares category files, builds the replacement images, validates Unbound configuration and migrates the stack. Existing device tokens, installed Apple profiles, shared policies, DNS hostname, TLS certificate and private block-page CA are retained. If the original console password was saved locally, it becomes the new dashboard password; otherwise installation prompts for a new one. Subsequent password changes are made in Settings. Migration creates a private backup under `/opt/dns-control-hub/backups/` and leaves the old resolver data under `data/` untouched. This is a configuration backup, not a guarantee that an already-corrupt old installation can be restored to working order.

**Keep device DNS disabled while migrating a broken installation.** Enable it once the installer prints `Local checks passed`. Images are built and configuration is validated before replacing running services. Deployment still briefly recreates containers; a single node cannot guarantee uninterrupted DNS during maintenance.

After migration, future updates are:

```bash
sudo update-live
```

Open `https://YOUR_DNS_HOSTNAME/`. Username: **admin**. The custom dashboard includes devices, profiles, category selections, site rules, private installation links, service/list status, block-page wording, password changes, theme selection and sign-out. There is no Technitium API dependency. Browser mutations use authenticated cookie sessions plus CSRF and origin checks; login attempts are rate limited. Credentials and management secrets stay on the VPS, outside GitHub.

## Profiles and devices

| Profile | Initially blocked categories |
| --- | --- |
| Default | Existing ads/malware, adult and gambling selection |
| Adults | Ads/malware |
| Kids | Ads/malware, adult and gambling |

Existing devices remain in Default. Move them in the dashboard's Devices page or through `sudo profiles`, action **4**. Their token and installed iPhone configuration remain valid. Edit profile categories in the dashboard or with the helper; repository updates do not reset them.

Add devices in the dashboard or run `sudo new`. Choose iOS, iPadOS, tvOS or macOS, and a shared profile. Each device gets its own private DoH token and private configuration download link. Helpers save files under `/root/<device-name>/`. Devices created in the dashboard can download immediately; a host timer exports their private files into those folders within about 30 seconds. No QR codes are printed. Do not share installation URLs or publish exported profiles.

Apple TV profile installation is experimental and varies by tvOS version. Provider instructions describe General > Privacy, selecting Share Apple TV Analytics, pressing Play and adding the profile URL. Apple does not document this DNS payload as universally supported on tvOS; test your device rather than assuming support.

## Block and allow rules

`sudo block` and `sudo unblock` both ask **device or site**. Device mode pauses/restores all new DNS queries for the chosen token. Site mode asks for a domain/URL and the target profiles, with an **All profiles** option. Shortcuts include `sudo block site`, `sudo unblock site`, `sudo block-site`, and `sudo unblock-site`. The dashboard provides the same actions.

A domain rule covers its hostname and descendants; DNS cannot filter a single URL path. `example.com` covers the whole domain; `www.example.com` covers that hostname and its descendants. An allow rule creates a category exception. The most specific custom rule wins, with allow winning an exact tie. Removing a rule restores ordinary category handling. CNAME/DNAME answer targets are checked too; allowing one domain does not automatically allow an unrelated blocked alias target.

Policies are evaluated before cached resolver answers. Returned DNS record TTLs are zero, preserving EDNS flags. Changes affect the next DNS request. **DNS cannot revoke cached IP addresses inside applications, disconnect existing streams, or control apps using their own resolver/direct IPs.** This is not a firewall or VPN kill switch. Unbound retains its upstream cache to reduce latency; it cannot bypass the gateway's current profile rules.

HaGeZi lists provide ads/malware, adult-content and gambling categories. No list covers every site. Files are validated before replacement, refreshed daily with hourly retries, and searched through read-only memory maps to avoid retaining large Python sets. Downloads have bounded socket/transfer waits and an official mirror fallback. Failed updates retain previous valid files; missing enabled lists or unknown profiles fail closed with DNS SERVFAIL. List sources are in `policy.json`.

## YouTube and block pages

YouTube service domains and video/CDN domains return the Albania proxy address **45.88.89.23**, including descendants. IPv6 and HTTPS/SVCB queries receive no alternative address hints. A validated maintained catalogue is refreshed daily. The Albania VPS must already provide a working SNI proxy, resolve upstream YouTube independently, and support the needed hostnames. This is DNS steering; it cannot guarantee capture of direct-IP traffic, alternative DNS, QUIC or ECH. DNS redirection alone is not an SNI proxy.

The block-page service serves pages only; it never forwards or decrypts ordinary allowed website traffic. It generates short-lived hostname certificates signed by the original private CA, with a bounded certificate-context cache and automatic leaf refresh. The CA's signing key is mounted only into this service, not the dashboard/DoH gateway. Trust the private CA on the Apple device for HTTPS block pages, including the manual full-trust setting where required. A public certificate for your DNS hostname cannot authenticate unrelated blocked website names. Existing CA trust is preserved during migration. Replace device profiles before the CA expires or if its key is compromised.

Test the page through your configured DNS at `http://blocked-probe.YOUR_DNS_HOSTNAME/` or HTTPS after trusting the CA. Settings changes its heading and message. The footer branding line has been removed.

## Two VPSs

Use different providers for better failure independence. Pair the second VPS using the private `/opt/dns-control-hub/exports/dns-pairing.tar.gz` bundle; it contains signing keys and must never be public. The public hostname points to the first VPS. The certificate is issued/renewed there and securely replicated to the second using hostname-verified TLS and a private management key. Retry timers handle temporary peer outages; prolonged offline periods can still cause certificate expiry.

Device membership, profile/category/site rules and block-page wording are synchronised with background retries every 30 seconds. The root helpers and dashboard mutations are restricted to the first VPS. Both nodes download category files independently, so snapshots can briefly differ. Read the helper/dashboard peer-sync result rather than assuming a change reached an offline VPS. Dashboard passwords and sessions are node-specific.

Upgrade both VPSs. Apple resolver selection is controlled by the OS; listing two IPs does not guarantee strict primary/secondary ordering. Test each public endpoint externally, then test with either VPS stopped before depending on failover.

## Validation and operation

GitHub checks exercise the real HTTP gateway, profile isolation, category/site exceptions, all-type device refusal, membership changes without token replacement, authenticated management sync, last-good list retention, missing-list failure, disk-backed membership, DNS TTL handling, cookie/CSRF/origin controls, password changes, and retained migration state. A Docker integration job builds and runs the actual Unbound, Python, Nginx and HAProxy stack with disposable credentials and a private test CA. It checks resolver transport, verified TLS, dashboard controls, YouTube address/hint handling, profile rules and HTTPS block pages. Browser tests exercise desktop/mobile login, device creation, category editing, settings and sign-out.

Integration fixtures use local test DNS zones. They do not prove the public VPS can reach authoritative servers, that the Albania proxy is reachable, or that a physical iPhone/Apple TV accepts a profile. Installer checks verify your live local stack with the real public certificate; public reachability and physical-device testing remain necessary.

```bash
sudo docker ps -a
sudo docker logs --tail 60 dns-control-hub-dns-1
sudo docker logs --tail 60 dns-control-hub-api-1
sudo journalctl -u dns-hub-certificate-sync.service -n 30
```

The resolver container uses Unbound's validating recursive mode with bounded cache sizes and packaged DNSSEC trust anchors. Update periodically to refresh the base image/packages. Public DNS requests pass through the private-token DoH gateway; plain resolver sockets are bound to localhost only. The custom block-page service handles other TLS hostnames through HAProxy.
