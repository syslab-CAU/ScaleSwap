#!/bin/bash

SESSION_NAME="dna"

compare_version="original"
kernel_version=$(uname -r)

result_path="dstat"
file_name="flip_t_$2_$1"

generate_unique_filename() {
	local base_name="$1"
	local extension="csv"
	local count=1

	local new_filename="${result_path}/${base_name}_${count}.${extension}"
	while [ -e "$new_filename" ]; do
		count=$((count + 1))
		new_filename="${result_path}/${base_name}_${count}.${extension}"
	done

	echo $new_filename
}

if [[ "$kernel_version" == *"$compare_version"* ]]; then
	result_path+="/original"
else
	result_path+="/proposed"
fi
mkdir -p ${result_path}

unique_filename=$(generate_unique_filename $file_name)
echo $unique_filename

cur_path=$(pwd)
echo "${cur_path}/${unique_filename}"
tmux new-session -d -s $SESSION_NAME "dstat -D md127,total --output ${cur_path}/${unique_filename}"
#tmux new-session -d -s $SESSION_NAME "dstat -D md126 --output ${cur_path}/${unique_filename}"

# test code
# do something
#~/workspace_cmh/swap/stress-no-time-limit/src/stress --vm 64 --vm-bytes 3G --vm-keep
for i in $(seq 1 $1); do
	python3 flip.py &
done

wait

tmux send-keys -t $SESSION_NAME C-c
sleep 1 

tmux kill-session -t $SESSION_NAME # 혹시 모르니 한번 더 종료
