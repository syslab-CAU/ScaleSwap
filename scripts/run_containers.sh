#!/bin/bash

if [ "$#" -ne 2 ]; then
	echo "Usage: $0 <container_num> <threads>"
	exit 1
fi

SESSION_NAME="macro_zip"  

RUN_CONTAINER=$1
THREADS=$2
cnt=2

echo "== ${RUN_CONTAINER} container =="
	# docker exec macro_zip1 ./benchmarks/gapbs/bfs -g 27 -n 3 &

	for i in $(seq 0 $(( $RUN_CONTAINER - 1 ))); do
		docker exec macro_zip$cnt ./benchmarks/dna/test.sh $THREADS &
		cnt=$(( $cnt + 1 ))
        done

	for i in $(seq 0 $(( $RUN_CONTAINER - 1 ))); do
		docker exec macro_zip$cnt ./benchmarks/image/flip.sh $THREADS &
		cnt=$(( $cnt + 1 ))
        done

	for i in $(seq 0 $(( $RUN_CONTAINER - 1 ))); do
		docker exec macro_zip$cnt ./benchmarks/image/gray_scale.sh $THREADS &
		cnt=$(( $cnt + 1 )) 
        done

	for i in $(seq 0 $(( $RUN_CONTAINER - 1 ))); do
		docker exec macro_zip$cnt ./benchmarks/python_list/test.sh $THREADS &
		cnt=$(( $cnt + 1 ))
        done


	docker exec macro_zip1 ./benchmarks/stress-no-time-limit_latency/src/stress --vm 1 --vm-bytes 20G --vm-keep &

        wait

echo "========= [done] =========="
