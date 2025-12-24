#!/bin/bash

SESSION_NAME="graph"

compare_version="combine"
kernel_version=$(uname -r)

result_path="dstat"
file_name="d_8_c_$1_t_$2_macros"

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
tmux new-session -d -s $SESSION_NAME "dstat --output ${cur_path}/${unique_filename}"

# test code
# do something
./run_containers.sh $1 $2

tmux send-keys -t $SESSION_NAME C-c
sleep 1 

tmux kill-session -t $SESSION_NAME # 혹시 모르니 한번 더 종료
