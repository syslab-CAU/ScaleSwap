SESSION_NAME=$2"_session"
echo $SESSION_NAME

total_size=$(( 96*3*1024 ))
size=$(( $total_size / $1 ))
test_result=$2
cur_path=$(pwd)
csv_file_path="${cur_path}"

echo 'Stress testing...'

# CSV 파일 저장 경로 설정
mkdir -p ${csv_file_path}
echo ${csv_file_path}

# tmux 세션에서 dstat 실행 (디스크 I/O 모니터링)
tmux new-session -d -s $SESSION_NAME "dstat -D total,md127 --output ${csv_file_path}/${total_size}_$1.csv"

# tmux 세션에서 sar 실행 (CPU 사용률 모니터링)
tmux split-window -h -t $SESSION_NAME "sar -u 1 > ${csv_file_path}/${total_size}_$1_sar.log"

sleep 1

# 스트레스 테스트 실행
sudo ../../../../stress-no-time-limit/src/stress --vm $1 --vm-bytes ${size}M --vm-keep

# 스트레스 테스트 종료 후 dstat와 sar 중지
tmux send-keys -t $SESSION_NAME C-c
sleep 1

tmux kill-session -t $SESSION_NAME

