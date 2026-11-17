#!/usr/bin/env sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
: "${CONFIG_DIR:?set CONFIG_DIR to dashboard-env/var/secrets}"
seed="$CONFIG_DIR/dashboard-auth-seed.sql"

if [ ! -f "$seed" ]; then
  echo "No $seed. Copy seeds/admin.sql.sample there and fill in the email, name and password hash."
  exit 1
fi
{ echo "BEGIN;"; cat "$seed"; echo "COMMIT;"; } | "$root/scripts/psql.sh" -q
echo "seeded $(basename "$seed")"
