#!/usr/bin/env sh
set -eu

root=$(cd "$(dirname "$0")/.." && pwd)
db="$root/scripts/psql.sh"

"$db" -q -c "CREATE TABLE IF NOT EXISTS schema_migrations (version text PRIMARY KEY, applied_at timestamptz NOT NULL DEFAULT now())"

for file in "$root"/migrations/*.sql; do
  version=$(basename "$file" .sql)
  if [ "$("$db" -Atc "SELECT 1 FROM schema_migrations WHERE version = '$version'")" = "1" ]; then
    echo "skip  $version"
    continue
  fi
  { echo "BEGIN;"; cat "$file"; echo "INSERT INTO schema_migrations (version) VALUES ('$version');"; echo "COMMIT;"; } | "$db" -q
  echo "apply $version"
done
