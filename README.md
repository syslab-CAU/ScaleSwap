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

## Run benchmark and show result
Run the benchmark after Swap on (**Module comile -> Setting All Flash Swap Arrays -> Swap on**)

### 1. Stress
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/stress
# ./test_with_dstat_stress_no_time_limit.sh
```
**show result**
(When the benchmark excuted, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 2. image(gray-scale)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/image_processing
# ./gray_scale_test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark excuted, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 3. image(flip)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/image_processing
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark excuted, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 4. dns\_visualization
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/dna_visualization
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark excuted, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 5. bfs
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/gapbs
# make -j $(nproc)
# cd ./fast26-test
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark excuted, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 6. python list
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/python_list
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark excuted, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```

# For AE (It will be deleted after AE)
### Proceed with the assumption that the kernel is already compiled
### Change to 6.6.8 Original linux kernel
```
$sudo su
# vim /etc/default/grub
(Please remove the annotation of the following line: #GRUB_DEFAULT="gnulinux-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e>gnulinux-6.6.8-scaleswap-original-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e")
# update-grub
# reboot
```
**Setting All Flash Swap Arrays**
After that, configure the All-Flash Swap Array and enable swap in the same way as ScaleSwap. Then, run the same benchmark scripts to collect results for comparison. (You can use the exact same scripts under <ScaleSwap>/ for both setups.)

 
