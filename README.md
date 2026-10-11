# DNS Control Hub

One or two private DNS VPSs with matching adult/gambling/ads/malware filtering, YouTube SNI redirects to **45.88.89.23**, per-device Apple profiles, HTTPS block pages, and root-only device helpers.

## Install

Requires one fresh **Ubuntu 24.04 or Debian 12/13** VPS for testing, or two for DNS redundancy. Each VPS needs public IPv4, Docker and ports TCP 80/443 available. Use different providers. Preserve SSH access. Public UDP/TCP 53 and direct port 5380 are not published; the admin console is available through HTTPS after password setup. Outbound DNS and HTTPS must be permitted.

**Certificate prerequisite:** enter any DNS hostname at install, either a domain you own or a provider-supplied hostname that permits public certificate issuance. Its A record must point only to VPS 1; remove an AAAA record unless it also reaches VPS 1. Keep TCP 80 reachable for certificate validation and renewal. No Netcup account or DNS API credentials are required. VPS 2 uses the same hostname/certificate through the explicit IP addresses in device profiles.

Run on VPS 1:

```bash
curl -fsSL https://raw.githubusercontent.com/waqaarhussain/dns-control-hub/main/install.sh | sudo bash
```

The installer prompts for the first DNS VPS IPv4 address, an optional second address, your DNS hostname, certificate email and this node's IP. Albania's IP is hardcoded. The certificate email is saved privately on the VPS.

**For a one-VPS test, leave the second IP blank.** Profiles contain only that VPS address, helpers act locally and no peer connections are attempted. There is no DNS redundancy.

For a two-VPS setup, transfer `/opt/dns-control-hub/exports/dns-pairing.tar.gz` privately from VPS 1 to `/root/dns-pairing.tar.gz` on VPS 2 using SCP/SFTP. Run the same installer on VPS 2 and enter that pairing file path. It preserves the shared block-page CA and device management identity. The bundle includes the public TLS certificate and its private key. VPS 1 renews it and securely replicates updates to VPS 2. New profile downloads require VPS 1 because the hostname points there; already-installed DNS profiles can use either IP.

Open TCP 80/443 in your provider firewall. The installer does not change a host firewall or SSH settings. Installation stops on failed DNS/TLS checks. Do not enable new profiles until both nodes pass and you test device switching.

## Helpers

Run device helpers on **VPS 1**, the device registry controller:

```bash
sudo new
sudo block
sudo unblock
```

| Command | What it does |
| --- | --- |
| `new` | Asks for device name and type: iOS, iPadOS, tvOS or macOS. Creates a unique private DNS token and profile. |
| `block` | Lists devices; selects a device by number or name; refuses every new DNS request through that device token, for every domain and record type. |
| `unblock` | Selects a device and enables its DNS requests again. |
| `update-live` | Downloads repository changes, restarts gateways, reapplies policy and reruns checks on the VPS where it runs. |

For a device named `Waqaar iPhone`, `new` saves:

```text
/root/waqaar-iphone/dns.mobileconfig
/root/waqaar-iphone/install-url.txt
/root/waqaar-iphone/device.json
/root/waqaar-iphone/README.txt
```

No terminal QR codes. Device folders are private, and the installer refuses to reuse unrelated existing folders. Profile download links are random private URLs; anyone with a link can obtain that device's DNS credentials. Keep them private.

Commands attempt immediate synchronisation to VPS 2 and report whether both nodes confirmed. If VPS 2 is unavailable, they explicitly report local-only success. The background service retries every 30 seconds. **Do not assume a device is blocked on both nodes until the command confirms both.** DNS continues independently on either VPS if the other goes down. Registry changes require VPS 1; this deliberate single writer avoids conflicting block/unblock decisions.

Blocking DNS is not a network firewall. Cached addresses, queries already in flight, existing streams, hardcoded IPs and alternative DNS/VPN providers may continue working. The profile is not a supervised enforcement mechanism. This helper does not disconnect an already-playing video.

## Apple installation

For iPhone/iPad, privately transfer `dns.mobileconfig` or open the URL in `install-url.txt`; install it from Settings > General > VPN & Device Management. For clean HTTPS block pages, enable full trust for **Private block-page CA** under Settings > General > About > Certificate Trust Settings if required. DoH itself uses publicly trusted TLS; the private CA is only for blocked website pages.

The profile has one DoH URL and both explicit server IP addresses. Apple does not promise strict primary/standby ordering or a fixed switch time. Test on the actual OS version, with each node stopped in turn.

**Apple TV is experimental.** The helper creates a `.mobileconfig` and HTTPS download link. DNS providers describe a hidden installation flow: Settings > General > Privacy, highlight Share Apple TV Analytics, press Play, then Add Profile and enter the URL. Menu names and behaviour vary. Apple's current DNSSettings documentation does not list tvOS in payload availability. Do not assume that installation means DNS is active. If it fails on your tvOS version, use a supported DNS/VPN app or router configuration instead; router-wide DNS cannot distinguish devices behind that router using these unique profile tokens.

Certificate-pinned apps may show an error rather than a block page. Trusting the block-page CA allows certificates signed by your DNS VPSs to be accepted by your device. Keep its private keys private.

## YouTube redirect and refresh

All managed YouTube hostnames, including video delivery via `googlevideo.com`, resolve to **45.88.89.23**. Apex and wildcard A records are overridden; managed primary zones return no public AAAA or HTTPS/SVCB records, avoiding those DNS routes bypassing the IPv4 proxy.

The initial domain list is a curated snapshot of AdGuard's maintained YouTube service definition plus additional API domains. A systemd service refreshes that definition daily with last-known-good fallback and validation before applying changes. Each node runs independently. Inspect it with:

```bash
systemctl status dns-hub-youtube.timer
journalctl -u dns-hub-youtube.service
```

The timer updates **domain rules**, not a list of YouTube destination IPs. This cannot capture unknown future hostnames, clients using alternative DNS, direct IP connections, or make an incompatible proxy forward QUIC/HTTP3 or Encrypted ClientHello. Some `ggpht.com` image hostnames are shared with other Google services; this catalogue can redirect those images too. Video and login behaviour must be tested on each client.

The existing Albania proxy must resolve real destinations with independent DNS. Pointing its own upstream resolver at these redirected DNS servers can loop. It must accept your client traffic for the configured domains and support TCP TLS forwarding. No changes are made to that VPS by this installer. This does not guarantee an ad-free YouTube experience or Google's country classification of that IP.

## Certificates and block page

acme.sh is installed at a pinned upstream revision, using **ZeroSSL with HTTP-01**. Its renewal cron is enabled on VPS 1. Renewals deploy the key/fullchain, reload Nginx and send the certificate to VPS 2 over authenticated, hostname-verified TLS. A timer retries replication every minute. The registration email comes from your private installer settings. This works with any DNS provider; changing the ACME client does not bypass certificate authority limits or provider CAA restrictions.

Keep both nodes online regularly so VPS 2 receives renewals before its old certificate expires. If it stays offline past expiry, repair it by privately copying the fresh pairing bundle's `tls` files to `/opt/dns-control-hub/tls/` and reloading Nginx; replication intentionally never disables TLS verification. Inspect `journalctl -u dns-hub-certificate-sync.service` on both nodes. Changing the configured DNS hostname requires new certificates and replacement device profiles.

HTTPS block pages use Technitium's Block Page app and the shared private CA, dynamically signing blocked hostnames. `blockpage.html` is a responsive custom light/dark page. A public certificate for your DNS hostname cannot authenticate unrelated blocked website hostnames. The root certificate embedded in device profiles enables those pages. The CA lasts 10 years; rebuild the identity and replace profiles before expiry or if a signing key leaks.

## Policy and dashboard

Edit `policy.json` in GitHub for category selections or extra redirect domains. HaGeZi ads/malware, adult and gambling lists are enabled and downloaded by each node every 24 hours. Snapshots may differ briefly; category selections match. Run **`sudo update-live` on both VPSs** after repository changes. Dashboard edits are not automatically copied to the other node and may be overwritten by the repository policy.

Open **https://YOUR_CONFIGURED_HOSTNAME/** for Technitium's browser login. On the first installation or upgrade enabling browser access, the installer requires you to choose and confirm a password of at least 12 characters. Username: **admin**. The console is not exposed until this step succeeds. HTTP requests redirect to HTTPS, while certificate challenges continue to work.

You can subsequently change your password through Technitium's user menu. A private non-expiring API token named **DNS Control Hub automation** keeps policy updates working independently of your login password. Do not delete that token; it is stored only in `/opt/dns-control-hub/admin-api-token`, outside GitHub. Browser password changes do not update the initial password file; use your chosen current password. Both DNS VPSs have separate console accounts/tokens; the public hostname normally reaches VPS 1.

Technitium manages DNS rules, blocklists, zones and statistics. The `new`/`block`/`unblock` device registry is separate and is still operated with the root helpers. Console policy edits are local to that server; repository-managed settings may be reapplied by updates and daily refreshes.

Public port 5380 remains closed. The HTTPS proxy exposes Technitium's own authenticated API and login page. Login requests are rate limited; unauthenticated protected API requests still require Technitium credentials. An optional SSH tunnel remains available: `ssh -L 5380:127.0.0.1:5380 root@YOUR_DNS_VPS_IP`, then http://localhost:5380.

## Validation and failure tests

Local tests cover single-VPS setup and operation, certificate hostname/key validation and renewal retry safety, profile/CA pairing, device isolation, DoH GET/POST, all-record-type blocking, unblock, unknown-token rejection, protected control requests, stale state not undoing a block, and malformed packets. They exercise a real local HTTP gateway with a test upstream. No live VPS, production ACME issuance, Albania proxy or physical Apple device was available during development.

Installation validates publicly trusted DoH TLS, an ordinary DNS answer, YouTube A redirection, a deterministic blocked domain and the HTTPS block page with the private CA. After installing both nodes:

1. Create a device with `new`, install its profile, test normal browsing and YouTube on Wi-Fi/mobile data.
2. Run `block`; require both-node confirmation. Verify an uncached hostname fails. Run `unblock`; verify it resolves again.
3. Stop VPS 1 containers and repeat browsing/block-policy checks using VPS 2.
4. Restore VPS 1; stop VPS 2 and repeat. Restore both.
5. Verify profile use on Apple TV separately; a successfully installed profile is not sufficient evidence.

Container commands: `sudo /opt/dns-control-hub/source/compose.sh -f /opt/dns-control-hub/compose.yaml stop` and `up -d`. Disable the profile if deployment checks fail. A single Albania proxy remains a separate point of failure for redirected traffic.

Back up `shared`, `tls`, `control`, `node.json`, `admin-api-token`, `data`, root device folders and `/root/.acme.sh` privately. Pairing bundles and acme account files contain sensitive keys. Never commit runtime files to GitHub. The Technitium image is pinned at 15.6.1; upgrades require explicit validation.

## Sources

- https://github.com/TechnitiumSoftware/DnsServer
- https://github.com/TechnitiumSoftware/DnsServer/blob/master/APIDOCS.md
- https://github.com/AdguardTeam/HostlistsRegistry/blob/main/services/youtube.yml
- https://github.com/acmesh-official/acme.sh/wiki/ZeroSSL.com-CA
- https://developer.apple.com/documentation/devicemanagement/dnssettings
- https://help.nextdns.io/t/35hncsv/apple-tv-and-profiles-an-easy-install
- https://github.com/hagezi/dns-blocklists
