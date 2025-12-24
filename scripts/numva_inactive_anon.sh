#!/usr/bin/env bash
# numa_inactive_anon.sh
set -euo pipefail

INTERVAL="${1:-1}"                # 기본 1초 (원하면 첫 번째 인자로 간격 지정)
PAGESIZE="$(getconf PAGESIZE)"

trap 'exit 0' INT TERM

while :; do
  echo "[$(date '+%Y-%m-%d %H:%M:%S')]"
  for f in /sys/devices/system/node/node*/vmstat; do
    node="$(basename "$(dirname "$f")")"
    pages="$(awk '/^nr_inactive_anon /{print $2}' "$f")"
    mib="$(awk -v p="$pages" -v ps="$PAGESIZE" 'BEGIN{printf("%.1f", p*ps/1024/1024)}')"
    printf "%s: nr_inactive_anon %s pages (%.1f MiB)\n" "$node" "$pages" "$mib"
  done
  echo
  sleep "$INTERVAL"
done

