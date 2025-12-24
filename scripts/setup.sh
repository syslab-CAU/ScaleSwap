# /home/syslab/workspace_cmh/swap/benchmark/docker/delete_docker.sh 128 &&
# sleep 1 &&

# /home/syslab/workspace_cmh/swap/benchmark/docker/create_containers.sh 128 &&
# sleep 1 &&

./insert_mod.sh
sleep 1 &&

/home/syslab/workspace_cmh/swap/script/swapfile_script/stripe.sh 2TB $1 &&
# /home/syslab/workspace_cmh/swap/script/swapfile_script/stripe.sh 2TB 4 &&
echo done

