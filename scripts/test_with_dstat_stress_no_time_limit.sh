#!/bin/bash

SESSION_NAME="stress_no_time_limit"

compare_version="recover"
kernel_version=$(uname -r)

result_path="dstat"
file_name="stress_no_time_limit_$2_$1"

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
	result_path+="/proposed"
else
	result_path+="/original"
fi
mkdir -p ${result_path}

unique_filename=$(generate_unique_filename $file_name)
echo $unique_filename

cur_path=$(pwd)
echo "${cur_path}/${unique_filename}"
#tmux new-session -d -s $SESSION_NAME "dstat -D md126,total --output ${cur_path}/${unique_filename}"
tmux new-session -d -s $SESSION_NAME "dstat -D md127 --output ${cur_path}/${unique_filename}"
#tmux new-session -d -s $SESSION_NAME "dstat -D nvme5n1 --output ${cur_path}/${unique_filename}"

# test code
# do something start

#../stress-no-time-limit_latency/src/stress --vm 128 --vm-bytes 2200M --vm-keep
#../stress-no-time-limit-taehwan/src/stress --vm 128 --vm-bytes 2200M --vm-keep
#../../stress-no-time-limit/src/stress --vm 128 --vm-bytes 2200M --vm-keep
#../../stress-no-time-limit/src/stress --vm 1 --vm-bytes 281600M --vm-keep
#../../stress-no-time-limit/src/stress --vm 2 --vm-bytes 140800M --vm-keep
#../../stress-no-time-limit/src/stress --vm 4 --vm-bytes 70400M --vm-keep
#../../stress-no-time-limit/src/stress --vm 8 --vm-bytes 35200M --vm-keep
#../../stress-no-time-limit/src/stress --vm 16 --vm-bytes 17600M --vm-keep
#../../stress-no-time-limit/src/stress --vm 32 --vm-bytes 8800M --vm-keep
#../../stress-no-time-limit/src/stress --vm 64 --vm-bytes 4400M --vm-keep
../stress-no-time-limit/src/stress --vm 128 --vm-bytes 2200M --vm-keep
#../stress-no-time-limit_latency/src/stress --vm 128 --vm-bytes 2200M --vm-keep
#taskset -c 1  ~/workspace_hwan/stress-no-time-limit-pinned/src/stress --vm 1 --vm-bytes 50G --vm-keep &
#stress --vm 128 --vm-bytes 2200M --vm-keep

# do something end

tmux send-keys -t $SESSION_NAME C-c
sleep 1 

tmux kill-session -t $SESSION_NAME # 혹시 모르니 한번 더 종료
