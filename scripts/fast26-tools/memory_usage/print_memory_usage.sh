#!/usr/bin/env bash
set -euo pipefail

interval="${1:-1}"   # seconds

max_total=0
max_ts=""
max_mem=0
max_swap=0

human() {
  if command -v numfmt >/dev/null 2>&1; then
    numfmt --to=iec --suffix=B "$1"
  else
    awk -v x="$1" 'BEGIN{printf "%.2fGiB", x/1024/1024/1024}'
  fi
}

report_and_exit() {
  echo
  echo "===== PEAK (free used + swap used, includes buff/cache) ====="
  echo "Timestamp: $max_ts"
  echo "Mem used:  $(human "$max_mem") ($max_mem bytes)"
  echo "Swap used: $(human "$max_swap") ($max_swap bytes)"
  echo "Total:     $(human "$max_total") ($max_total bytes)"
  exit 0
}
trap report_and_exit INT TERM

while true; do
  ts="$(date '+%F %T')"

  # free -b:
  # Mem:  total used free shared buff/cache available
  # Swap: total used free
  read -r mem_used swap_used < <(
    free -b | awk '
      /^Mem:/  {mu=$3}
      /^Swap:/ {su=$3}
      END {print mu, su}
    '
  )

  total=$(( mem_used + swap_used ))

  if (( total > max_total )); then
    max_total=$total
    max_ts="$ts"
    max_mem=$mem_used
    max_swap=$swap_used
  fi

  sleep "$interval"
done

