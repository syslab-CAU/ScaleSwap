while :; do
  awk '
    /^MemTotal:/{mt=$2} /^MemFree:/{mf=$2}
    /^SwapTotal:/{st=$2} /^SwapFree:/{sf=$2} /^SwapCached:/{sc=$2}
    END{
      mem_used = (mt - mf) / 1024;       # MB 단위로 변환
      swap_used = (st - sf) / 1024;      # MB 단위로 변환
      swap_cached = sc / 1024;           # MB 단위로 변환
      adj = mem_used + swap_used - swap_cached;
      printf "%s mem_used=%.2fMB swap_used=%.2fMB swap_cached=%.2fMB adj_sum=%.2fMB\n",
             strftime("%F %T"), mem_used, swap_used, swap_cached, adj;
    }' /proc/meminfo | tee -a "mem_log/memswap_$(date +%F_%H%M).log"
  sleep 2
done
