#!/usr/bin/env bash
set -Eeuo pipefail
BASE=/opt/dns-control-hub
# First certificate installation precedes container creation.
if [[ -f $BASE/compose.yaml ]] && [[ -n $("$BASE/source/compose.sh" -f "$BASE/compose.yaml" ps -q doh) ]]; then
  "$BASE/source/compose.sh" -f "$BASE/compose.yaml" exec -T doh nginx -t
  "$BASE/source/compose.sh" -f "$BASE/compose.yaml" exec -T doh nginx -s reload
fi
# Best effort now; the certificate sync timer retries if VPS 2 is offline.
python3 "$BASE/source/certificate_sync.py" send
