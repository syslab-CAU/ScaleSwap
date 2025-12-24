#!/bin/bash

SESSION_NAME="GAB_SESSION"

#compare_version="swap-profiling"
compare_version="original"
kernel_version=$(uname -r)

result_path="dstat"
file_name="bfs_g30_n5_t128_d_$1"

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
	filename+="_original"
else
	result_path+="/proposed"
	filename+="_proposed"
fi
mkdir -p ${result_path}

unique_filename=$(generate_unique_filename $file_name)
echo $unique_filename


cur_path=$(pwd)
#tmux new-session -d -s $SESSION_NAME "dstat -D md126 --output ${cur_path}/${unique_filename}"
tmux new-session -d -s $SESSION_NAME "dstat -D md127 --output ${cur_path}/${unique_filename}"

# test code
# ../bfs -g 25 -n 5 & 
# ../bfs -g 25 -n 5 &
../bfs -g 30 -n 5
#../bfs -g 29 -n 5
# ../bfs -u 28 -n 5 
# ../pr -g 28 -n 5 & 
# ../pr -g 28 -n 5

# wait

tmux send-keys -t $SESSION_NAME C-c
sleep 1 

tmux kill-session -t $SESSION_NAME # 혹시 모르니 한번 더 종료

# curl "http://165.194.35.14:8000/done"
