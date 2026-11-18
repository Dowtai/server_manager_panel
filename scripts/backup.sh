#!/bin/sh
set -eu
umask 077
backup_dir=${1:?Usage: scripts/backup.sh /absolute/backup/directory}
mkdir -p "$backup_dir"
# Keep .env with the encryption key encrypted and separate from the DB backup.
docker compose exec -T db pg_dump -U awgpanel -d awgpanel -Fc > "$backup_dir/awg-panel-$(date -u +%Y%m%dT%H%M%SZ).dump"
