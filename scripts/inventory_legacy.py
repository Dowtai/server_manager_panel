#!/usr/bin/env python3
"""Read-only inventory of the legacy bot; never connects to managed VPS."""
import argparse
import ipaddress
import json
from pathlib import Path
import sqlite3

parser = argparse.ArgumentParser()
parser.add_argument("database", type=Path)
args = parser.parse_args()
path = args.database.resolve(strict=True)
db = sqlite3.connect(path.as_uri() + "?mode=ro", uri=True)
db.row_factory = sqlite3.Row
db.execute("PRAGMA query_only=ON")
tables = {r[0] for r in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
table = "servers" if "servers" in tables else "server" if "server" in tables else None
if not table:
    raise SystemExit("No legacy servers table found")
result = {"source": str(path), "servers": [], "requires_separate_migration": True}
for row in db.execute(f"SELECT * FROM {table}"):
    server = dict(row)
    cfg = json.loads(server.get("config_json") or "{}")
    endpoint = server.get("endpoint", "")
    try:
        ipaddress.ip_address(endpoint)
        needs_new_domain_profile = True
    except ValueError:
        needs_new_domain_profile = False
    peers = []
    if "peers" in tables:
        columns = {r[1] for r in db.execute("PRAGMA table_info(peers)")}
        query = "SELECT id,telegram_id,name,address,public_key,revoked_at FROM peers"
        params = ()
        if "server_id" in columns:
            query += " WHERE server_id=?"
            params = (server["id"],)
        peers = [dict(p) for p in db.execute(query, params)]
    result["servers"].append({
        "legacy_id": server["id"], "name": server.get("name", "default"),
        "management_host": server["host"], "endpoint": endpoint,
        "subnet": cfg.get("subnet"), "udp_port": cfg.get("port"),
        "server_key_material_present": bool(cfg.get("server_private")),
        "client_private_keys_recoverable": False,
        "domain_profiles_need_reissue": needs_new_domain_profile,
        "peers": peers,
    })
db.close()
print(json.dumps(result, ensure_ascii=False, indent=2))
