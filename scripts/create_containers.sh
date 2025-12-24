#!/bin/bash

# 제작할 container 개수
MAX_INDEX=$1
IMAGE_NAME="benchmark_zip:06"  # 사용하려는 Docker 이미지 이름 설정
CORE=128

declare -A pid_array # 백그라운드 프로세스의 pid를 담는 배열

for i in $(seq 1 "$MAX_INDEX"); do
    CONTAINER_NAME="macro_zip$i"

    # 컨테이너가 존재하는지 확인
    CONTAINER_ID=$(docker ps -a --filter "name=^/${CONTAINER_NAME}$" --format "{{.ID}}")

    if [ -n "$CONTAINER_ID" ]; then
        if [ "$(docker ps --filter "name=^/${CONTAINER_NAME}$" --format "{{.ID}}")" ]; then
        	# case1. 컨테이너가 이미 실행 중
            echo "컨테이너 $CONTAINER_NAME 가 이미 실행 중입니다."
        else
       		# case2. 컨테이너가 존재하지만 실행 중이지 않다면 시작
            echo "컨테이너 $CONTAINER_NAME 이 존재하지만 실행 중이 아닙니다. 실행 시키겠습니다."
            docker start "$CONTAINER_NAME" &
        fi  
    else
        # case3. 컨테이너가 존재하지 않으므로 새로 생성
        # background 프로세스로 진행되게 하여 제작 속도를 높임
        echo "컨테이너 $CONTAINER_NAME 이 없습니다. 새로 생성합니다."
	# docker run -dit --cpuset-cpus=$(( i % CORE )) --name "$CONTAINER_NAME" "$IMAGE_NAME" /bin/bash &
	docker run -v /mnt/test/latency:/latency -dit --privileged --name "$CONTAINER_NAME" "$IMAGE_NAME" /bin/bash &
        pid_array[$CONTAINER_NAME]=$!
    fi  
done

for CONTAINER_NAME in "${!pid_array[@]}"; do
        PID=${pid_array[$CONTAINER_NAME]}

        wait "$PID"
        echo "컨테이너 $CONTAINER_NAME의 생성이 완료되었습니다. "
        docker start "$CONTAINER_NAME" &
done

wait
