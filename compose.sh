#!/usr/bin/env bash
set -Eeuo pipefail
# These are unattended commands. Compose exec otherwise consumes the remaining
# installer when the installer is streamed into bash through curl.
if docker compose version >/dev/null 2>&1; then
  exec docker compose "$@" </dev/null
else
  exec docker-compose "$@" </dev/null
fi
