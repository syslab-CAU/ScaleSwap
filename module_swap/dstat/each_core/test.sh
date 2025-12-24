for i in $(seq 1 5); do
	echo $i
	./test_with_dstat.sh 8
	sleep 20
	python3 /home/syslab/workspace_cmh/scripts/dstat_average.py -h dstat/original/dna_result_$i.csv
done
