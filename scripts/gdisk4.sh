#!/bin/bash
# Usage: ./partition_by_core.sh /dev/md127 [core_count]
# 만약 두 번째 인자가 없으면 nproc로 코어 수를 자동으로 사용합니다.

if [ "$#" -lt 1 ]; then
    echo "Usage: $0 <device> [core_count]"
    exit 1
fi

DEVICE="$1"

# 코어 수가 인자로 주어지면 사용, 아니면 nproc로 계산
if [ -n "$2" ]; then
    CORE_COUNT="$2"
else
    CORE_COUNT=$(nproc)
fi

# 기존 파티션 테이블 초기화 (있다면 모두 삭제)
echo "Clearing existing partition table on $DEVICE..."
sgdisk --zap-all "$DEVICE"

# 여기서는 디바이스 전체 크기가 14950GB라고 가정합니다.
#TOTAL_SIZE=14950   # GB
TOTAL_SIZE=7000   # GB
#TOTAL_SIZE=3686   # GB
# 파티션 크기는 총 크기를 코어 수로 나눈 값 (정수 계산)
PART_SIZE=$(echo "$TOTAL_SIZE / $CORE_COUNT" | bc)

echo "Device: $DEVICE"
echo "Core count: $CORE_COUNT"
echo "Creating $CORE_COUNT partitions, each of size ${PART_SIZE}G"

# 각 파티션 생성 (sgdisk의 --new 옵션은 자동으로 시작 섹터를 계산합니다)
for i in $(seq 1 $CORE_COUNT); do
    echo "Creating partition $i: size +${PART_SIZE}G"
    sgdisk --new=$i:0:+${PART_SIZE}G "$DEVICE"
done

echo "Partitioning complete."

