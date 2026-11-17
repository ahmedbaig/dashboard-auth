#!/usr/bin/env sh
set -eu

: "${CONFIG_DIR:?set CONFIG_DIR to dashboard-env/var/secrets}"

conn=$(python3 - "$CONFIG_DIR/db-handler-db.json" <<'PY'
import json, sys
c = next(x for x in json.load(open(sys.argv[1]))["connections"] if x["database"] == "dashboard")
mode = c.get("params", {}).get("sslmode", "require")
print(f"host={c['host']} port={c.get('port', 5432)} user={c['user']} dbname={c['name']} sslmode={mode}")
PY
)
PGPASSWORD=$(python3 -c "import json,sys; print(next(x for x in json.load(open(sys.argv[1]))['connections'] if x['database']=='dashboard')['password'])" "$CONFIG_DIR/db-handler-db.json")
export PGPASSWORD

exec psql "$conn" -v ON_ERROR_STOP=1 "$@"
