#!/bin/bash
# Usage: ./enable_swap.sh /dev/md127 <start_partition> <end_partition>
# 예) ./enable_swap.sh /dev/md127 1 128

if [ "$#" -ne 3 ]; then
    echo "Usage: $0 <device> <start_partition> <end_partition>"
    exit 1
fi

DEVICE="$1"
START="$2"
END="$3"

for i in $(seq "$START" "$END"); do
    PARTITION="${DEVICE}p${i}"
    echo "Processing $PARTITION ..."
    
    # mkswap으로 스왑 영역 초기화
    if sudo mkswap "$PARTITION"; then
        echo "mkswap successful on $PARTITION"
    else
        echo "mkswap failed on $PARTITION"
        continue
    fi

    # swapon으로 스왑 활성화
    if sudo swapon -p 1 "$PARTITION"; then
#    if sudo swapon "$PARTITION"; then
        echo "swapon successful on $PARTITION"
    else
        echo "swapon failed on $PARTITION"
    fi
done

echo "Swap setup complete."

