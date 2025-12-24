#watch -n1 "bash -lc 'swapon --show=NAME,TYPE,SIZE,USED,PRIO \
#  | grep -E \"^(NAME|[^[:space:]]*([^0-9]|^)(1|2|66|67)([^0-9]|$)[^[:space:]]*)\"'"


watch -n1 "swapon -s"
