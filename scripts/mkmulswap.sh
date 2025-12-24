#!/bin/bash

dir='/mnt/test/'
total=14500*1024
#total=500*1*1024
# total=440*1024
size=$(( $total / $1 ))

#sudo rm -rf /mnt/test/*
echo "create $1 files (each ${size}MB)"
for i in $(seq 1 $1)
do
	sudo fallocate -l ${size}MB "$dir"swapfile"$i" 
	sudo chmod 600 "$dir"swapfile"$i" 
	sudo mkswap "$dir"swapfile"$i" 
#	sudo swapon "$dir"swapfile"$i" 
	sudo swapon -p 1 "$dir"swapfile"$i" 
	# sudo swapon "$dir"swapfile"$i"

done
echo "All done."
