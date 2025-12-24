for i in $(seq 0 7); do
	# for j in $(seq 1 128); do
		# swapoff /mnt/test$i/swapfile$j
		# rm /mnt/test$i/swapfile$j
	# done

	swapoff -a
	umount /mnt/test$i
done

/home/syslab/workspace_cmh/swap/combine_proposed_scheme/swap/remove_mod.sh
