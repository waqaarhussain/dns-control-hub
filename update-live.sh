#!/usr/bin/env bash
set -Eeuo pipefail
[[ $EUID == 0 ]] || { echo 'Run sudo update-live'; exit 1; }
BASE=/opt/dns-control-hub
cd "$BASE/source"
if [[ ${1:-} != --no-pull ]]; then git pull --ff-only; fi
python3 hub.py render
python3 hub.py console
./compose.sh -f "$BASE/compose.yaml" build
./compose.sh -f "$BASE/compose.yaml" run --rm --no-deps dns unbound-checkconf /etc/unbound/hub.conf
./compose.sh -f "$BASE/compose.yaml" up -d --force-recreate --remove-orphans
python3 hub.py check
python3 devices.py export-pending
printf '\nReady. Dashboard: '
python3 -c 'import json; print("https://"+json.load(open("/opt/dns-control-hub/shared/settings.json"))["hostname"]+"/")'
