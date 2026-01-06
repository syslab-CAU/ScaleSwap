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
# mdadm --stop /dev/md126
# cd <ScaleSwap>/scripts
# ./check_model (we only use 8 FireCuda in our server)
# mdadm --create /dev/md127 --raid-devices=8 --level=0 /dev/nvme{}n1 (fill 8 FireCuda's nvme number in our server). Please don't select Intel's nvme!!!!
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
**Use ScaleSwap kernel**
```
$ sudo su
# vim /etc/default/grub
GRUB_DEFAULT="gnulinux-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e>gnulinux-6.6.8-ScaleSwap-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e"
GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all"
# update-grub && reboot
```

Run the benchmark after Swap on (**Module comile -> Setting All Flash Swap Arrays -> Swap on**)

### 1. Stress (Figure 1, 12, 16), (Table 2)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/stress
# ./test_with_dstat_stress_no_time_limit.sh
```
**show result**
(When the benchmark finished, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 2. image(gray-scale) (Figure 13)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/image_processing
# ./gray_scale_test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark finished, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 3. image(flip) (Figure 13)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/image_processing
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark finished, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 4. dns\_visualization (Figure 13)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/dna_visualization
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark finished, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 5. bfs (Figure 13)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/gapbs
# make -j $(nproc)
# cd ./fast26-test
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark finished, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```


### 6. python list (Figure 13)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/python_list
# ./test_with_dstat.sh 128 (# of cores)
```
**show result**
(When the benchmark finished, 
a CSV file is created under ./dstat/proposed with increasing indices, e.g., \*\_1.csv, \*\_2.csv.)
```
# cd ./dstat
# python3 dstat_average.py proposed/<*.csv> -h
```

### 7. Latency (Table 1)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/latency
# ./test_with_dstat.sh
```
**show result**
(When the benchmark finished, 
log files are created under ./ with increasing indices, e.g., *_XXX.log, *_YYY.log.)
```
# python3 print_latency.py XXX YYY -h
```

### 8. Memory usage (Figure 15), (Table 3)
**run benchmark**
```
$ sudo su
# cd <ScaleSwap>/scripts/fast26-tools/memory_usage
# ./print_memory_usage.sh
```
Using a tool such as tmux, open an additional pane/window. **While the script is running, run "1. Stress"**. After the stress workload finishes, terminate the script with Ctrl+C; the script will then print the peak memory_usage.

# For AE 
## Orignal kernel
### Proceed with the assumption that the kernel is already compiled
### Change to 6.6.8 Original linux kernel
```
$sudo su
# vim /etc/default/grub
GRUB_DEFAULT="gnulinux-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e>gnulinux-6.6.8-scaleswap-original-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e"
# update-grub
# reboot
```
**Setting All Flash Swap Arrays and mount**
```
$ sudo su
# mdadm --stop /dev/md127
# mdadm --stop /dev/md126
# cd <ScaleSwap>/scripts
# ./check_model (we only use 8 FireCuda in our server)
# mdadm --create /dev/md127 --raid-devices=8 --level=0 /dev/nvme{}n1 (fill 8 FireCuda's nvme number in our server). Please don't select Intel's nvme!!!!
# mkfs -t ext4 -E lazy_itable_init=0,lazy_journal_init=0 -O ^has_journal /dev/md127
# mount /dev/md127 /mnt/test
# cd <ScaleSwap>/scripts
# ./mkmulswap.sh 128 (# of cores)
```
### After that, run the same benchmark scripts to collect results for comparison. (You can use the exact same scripts under <ScaleSwap>/ for both setups.)



## EXTMEM (Figure 16)
### Original Swap for Extmem
**run benchmark**
```
$ sudo su
# vim /etc/default/grub
GRUB_DEFAULT="gnulinux-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e>gnulinux-5.15.0-Extmem+-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e"
# update-grub && reboot
```
Set **"Setting All Flash Swap Arrays"**
```
# mount /dev/md127 /mnt/test
# fallocate -l 400G /mnt/test/extmem_swapfile
# chmod 600 /mnt/test/extmem_swapfile
# mkswap /mnt/test/extmem_swapfile
# swapon /mnt/test/extmem_swapfile
# cd /home/syslab/workspace_hwan/Extmem/ExtMem/run-scripts
# ./run-mmapbench.sh
```
**show result**
When the benchmark is finished, <log file> is created
```
# vim <log file>
```

### ScaleSwap for Extmem
**run benchmark**
```
$ sudo su
# vim /etc/default/grub
GRUB_DEFAULT="gnulinux-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e>gnulinux-6.6.8-ScaleSwap-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e"
# update-grub && reboot
```
Set **Module comile -> Setting All Flash Swap Arrays -> Swap on**
```
# cd /home/syslab/workspace_hwan/Extmem/ExtMem/run-scripts
# ./run-mmapbench-scaleswap.sh
```
**show result**
When the benchmark is finished, <log file> is created
```
# vim <log file>
```

## TMO (Figure 15)
**Please, don't use ScaleSwap kernel. You can use scaleswap-original kernel**
```
$ sudo su
# vim /etc/default/grub
GRUB_DEFAULT="gnulinux-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e>gnulinux-6.6.8-scaleswap-original-advanced-6b7e64a0-90bb-4d86-af47-ec019c73664e"
GRUB_CMDLINE_LINUX="systemd.unified_cgroup_hierarchy=1 cgroup_no_v1=all"
# update-grub && reboot
```

```
$ sudo su
# sh -c "echo Y > /sys/module/zswap/parameters/enabled"
# cat /sys/kernel/debug/zswap/pool_total_size (# 압축된 총 메모리 양 확인)

# echo 40 | sudo tee /sys/module/zswap/parameters/max_pool_percent
# echo zstd | tee /sys/module/zswap/parameters/compressor
```
**run benchmark**
First, set **"Setting All Flash Swap Arrays -> Swap on"**
Second, run **“8. memory usage”**
Third, run **“2. image (grayscale)”, “3. image (flip)”, and “4. dns_visualization” simultaneously**.
**show result**
Fourth, When evaluation finished, **stop "8. memory uage" script**, then you can show the total memory usage
