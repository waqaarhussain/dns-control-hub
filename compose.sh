#!/usr/bin/env bash
set -Eeuo pipefail
if docker compose version >/dev/null 2>&1; then
  exec docker compose "$@"
else
  exec docker-compose "$@"
fi
