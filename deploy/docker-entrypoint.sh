#!/bin/sh
set -eu

data_dir=${ANQUAN_DATA_DIR:-/data/anquan}
# A new host bind mount is owned by root. Prepare it before dropping privileges.
if [ "$(id -u)" -eq 0 ]; then
  mkdir -p "$data_dir"
  chown anquan:anquan "$data_dir"
  chmod 0700 "$data_dir"
  for file in "$data_dir/anquan.db" "$data_dir/anquan.db-wal" "$data_dir/anquan.db-shm"; do
    if [ -f "$file" ]; then
      chown anquan:anquan "$file"
      chmod 0600 "$file"
    fi
  done
fi
case "${1:-}" in
  ''|serve|reset-admin|-*) set -- /app/anquan-master "$@" ;;
esac
if [ "$(id -u)" -eq 0 ]; then
  exec su-exec anquan:anquan "$@"
fi
exec "$@"
