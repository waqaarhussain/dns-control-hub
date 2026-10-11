#!/usr/bin/env bash
set -Eeuo pipefail
trap 'echo "Installation stopped at line $LINENO. Fix the error and rerun; do not install the iPhone profile until checks pass." >&2' ERR
[[ $EUID == 0 ]] || { echo 'Run as root (sudo bash).'; exit 1; }
. /etc/os-release
[[ ${ID:-} == ubuntu || ${ID:-} == debian ]] || { echo 'Requires a fresh Ubuntu or Debian VPS.'; exit 1; }
export DEBIAN_FRONTEND=noninteractive
apt-get update
apt-get install -y ca-certificates curl git python3 openssl docker.io cron socat
if apt-cache show docker-compose-v2 >/dev/null 2>&1; then
  apt-get install -y docker-compose-v2
elif apt-cache show docker-compose-plugin >/dev/null 2>&1; then
  apt-get install -y docker-compose-plugin
else
  apt-get install -y docker-compose
fi
systemctl enable --now docker
BASE=/opt/dns-control-hub
mkdir -p "$BASE"
chmod 700 "$BASE"
if [[ ! -d $BASE/source/.git ]]; then
  git clone https://github.com/waqaarhussain/dns-control-hub.git "$BASE/source"
else
  git -C "$BASE/source" pull --ff-only
fi
python3 "$BASE/source/hub.py" setup
# Pinned acme.sh revision; HTTP validation works independently of DNS provider.
is_controller=$(python3 -c 'import json; p="/opt/dns-control-hub/"; print(json.load(open(p+"node.json"))["public_ip"] == json.load(open(p+"shared/settings.json"))["dns_ips"][0])')
if [[ $is_controller == True && ! -x /root/.acme.sh/acme.sh ]]; then
  acme_src=$(mktemp -d)
  git -C "$acme_src" init -q
  git -C "$acme_src" fetch -q --depth=1 https://github.com/acmesh-official/acme.sh.git 807da6498377ee5e0cf43a78091f46f12dc59a89
  git -C "$acme_src" checkout -q FETCH_HEAD
  cert_email=$(python3 -c 'import json; print(json.load(open("/opt/dns-control-hub/shared/settings.json"))["acme_email"])')
  (cd "$acme_src" && ./acme.sh --install -m "$cert_email")
  rm -rf "$acme_src"
fi
if [[ -d /root/.acme.sh ]]; then chmod 700 /root/.acme.sh; fi
systemctl enable --now cron
python3 "$BASE/source/hub.py" certificates
python3 "$BASE/source/devices.py" helpers
cat > /usr/local/bin/update-live <<'SCRIPT'
#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run sudo update-live'; exit 1; }
cd /opt/dns-control-hub/source
git pull --ff-only
python3 devices.py helpers
python3 hub.py render
/opt/dns-control-hub/source/compose.sh -f /opt/dns-control-hub/compose.yaml up -d
python3 hub.py console
python3 hub.py render
/opt/dns-control-hub/source/compose.sh -f /opt/dns-control-hub/compose.yaml restart api doh gateway
python3 hub.py apply
python3 hub.py check
SCRIPT
chmod 755 /usr/local/bin/update-live
python3 "$BASE/source/hub.py" render
"$BASE/source/compose.sh" -f "$BASE/compose.yaml" up -d
python3 "$BASE/source/hub.py" console
python3 "$BASE/source/hub.py" render
"$BASE/source/compose.sh" -f "$BASE/compose.yaml" exec -T doh nginx -t
"$BASE/source/compose.sh" -f "$BASE/compose.yaml" exec -T doh nginx -s reload
python3 "$BASE/source/hub.py" apply
python3 "$BASE/source/hub.py" check
cat > /etc/systemd/system/dns-hub-youtube.service <<'UNIT'
[Unit]
Description=Refresh maintained YouTube DNS service catalogue
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/dns-control-hub/source/hub.py refresh-youtube
TimeoutStartSec=600
UNIT
cat > /etc/systemd/system/dns-hub-youtube.timer <<'UNIT'
[Unit]
Description=Refresh YouTube domains daily
[Timer]
OnCalendar=daily
RandomizedDelaySec=3600
Persistent=true
[Install]
WantedBy=timers.target
UNIT
cat > /etc/systemd/system/dns-hub-certificate-sync.service <<'UNIT'
[Unit]
Description=Replicate renewed DNS certificate between VPSs
After=docker.service network-online.target
[Service]
Type=oneshot
ExecStart=/usr/bin/python3 /opt/dns-control-hub/source/certificate_sync.py tick
UNIT
cat > /etc/systemd/system/dns-hub-certificate-sync.timer <<'UNIT'
[Unit]
Description=Retry DNS certificate replication
[Timer]
OnBootSec=30
OnUnitActiveSec=60
[Install]
WantedBy=timers.target
UNIT
systemctl daemon-reload
systemctl enable --now dns-hub-youtube.timer dns-hub-certificate-sync.timer
printf '\nReady. Run sudo new to create a device profile.\n'
python3 -c 'import json; print("Admin dashboard: https://" + json.load(open("/opt/dns-control-hub/shared/settings.json"))["hostname"] + "/ (username admin)")'
printf 'Pairing bundle: %s/exports/dns-pairing.tar.gz. Keep it private.\n' "$BASE"
