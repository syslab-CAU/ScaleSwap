#!/bin/sh

make -j 64 && 
make install && 
sudo modprobe -v swap && 

nvme_result="./ext4_multiple_swapfile_nvme0n1.txt"
all_result="./ext4_multiple_swapfile.txt"

echo 'stress testing...' 
# dstat -D nvme0n1,nvme1n1,nvme2n1,nvme3n1 > $nvme_result &
# dstat > $all_result &
# sudo ../../stress-no-time-limit/src/stress --vm 72 --vm-bytes 1500M --vm-keep

for i in $(seq 11)
do
	(sudo ../../stress-no-time-limit/src/stress --vm 1 --vm-bytes 9818M --vm-keep) &
	echo $!
done

WORK_PID=`jobs -l | awk '{print $2}'`
echo `jobs -l`
wait $WORK_PID

# sudo ../../stress-no-time-limit/src/stress --vm 36 --vm-bytes 1500M --vm-keep
# sudo killall dstat


echo 'rmmod kswap ...'
sudo modprobe -r -v swap
make clean
echo 'kswap removed, check "demsg"'

# python3 ./disk_average.py $nvme_result -h
# python3 ./disk_average.py $all_result -h
