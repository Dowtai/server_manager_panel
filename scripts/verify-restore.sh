#!/bin/sh
# Destructive only to the dedicated temporary database created by this script.
set -eu
dump=${1:?Usage: scripts/verify-restore.sh path/to/backup.dump}
test -f "$dump"
restore_db="restore_check_$(date +%s)_$$"
cleanup() { docker compose exec -T db dropdb -U awgpanel --if-exists "$restore_db" >/dev/null; }
trap cleanup EXIT INT TERM
docker compose exec -T db createdb -U awgpanel "$restore_db"
docker compose exec -T db pg_restore -U awgpanel -d "$restore_db" --no-owner --exit-on-error < "$dump"
docker compose exec -T db psql -U awgpanel -d "$restore_db" -v ON_ERROR_STOP=1 -c 'SELECT count(*) AS instances FROM instances; SELECT count(*) AS devices FROM devices;'
