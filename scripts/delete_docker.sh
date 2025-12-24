#!/bin/bash 

declare -A pid_array

for i in $(seq 1 $1)
do
	CONTAINER_NAME="macro_zip$i"

        echo "${i} stop docker"
        docker stop "$CONTAINER_NAME" &
	pid_array[$CONTAINER_NAME]=$!
done

for CONTAINER_NAME in "${!pid_array[@]}"; do
	PID=${pid_array[$CONTAINER_NAME]}

	wait "$PID"
	docker rm "$CONTAINER_NAME" &
done

wait
