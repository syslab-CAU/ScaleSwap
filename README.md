# ScaleSwap: A Scalable OS Swap System for All-Flash Swap Arrays

## Getting started

Clone this repository and set up its submodules. 

**Git clone**
```
sudo apt-get update
sudo apt-get install -y git-lfs
git lfs install

git clone git@github.com:ScaleSwap-All-Flash/ScaleSwap.git
```

**Kernel compile**
```
$ sudo su
# cd  <ScaleSwap>/linux-6.6.8/
# make menuconfig
# make -j $(nproc)
# make -j $(nproc) INSTALL_MOD_STRIP=1 modules_install
# make -j $(nproc) install
```

**Module comile**
```
$ sudo su
# cd <ScaleSwap>/module_swap/
# make -j $(nproc)
```

**Setting All Flash Swap Arrays**

```
$ sudo su
# mdadm --stop /dev/md127
# cd <ScaleSwap>/scripts
# ./check_model (we only use 8 FireCuda in our server)
# mdadm --create /dev/md127 --raid-devices=8 --level=0 /dev/nvme{}n1 (fill 8 FireCuda's nvme number in our server)
# mkfs -t ext4 -E lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal /dev/md127
```

**Swap on**
```
$ sudo su
# cd <ScaleSwap>/module_swap/
# ./insert_mod.sh
# mount /dev/md127 /mnt/test
# cd <ScaleSwap>/scripts
# ./mkmulswap.sh 128 (# of cores)
```

**Swap off**
```
$ sudo su
# swapoff -a
# cd <ScaleSwap>/module_swap
# ./remove_mod.sh
# umount /mnt/test
```

## Run benchmark
### When the test_with_dstat.sh executed below finishes running, a CSV file is created in ./dstat/proposed within the same directory.
You can check the throughput using the command below.
```
$ sudo su
# cd dstat
# python3 dstat proposed/<*.csv> -h
```


**stress**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/stress
# ./test_with_dstat_stress_no_time_limit.sh
```

**image(gray-scale)**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/image_processing
# ./gray_scale_test_with_dstat.sh 128 (# of cores)
```

**image(flip)**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/image_processing
# ./test_with_dstat.sh 128 (# of cores)
```

**dns_visualization**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/dna_visualization
# ./test_with_dstat.sh 128 (# of cores)
```

**bfs**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/gapbs
# make -j $(nproc)
# cd ./fast26-test
# ./test_with_dstat.sh 128 (# of cores)
```

**python list**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/python_list
# ./test_with_dstat.sh 128 (# of cores)
```
