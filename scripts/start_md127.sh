sudo mdadm --create /dev/md127 --raid-devices=8 --level=0 /dev/nvme{2,3,4,6,7,8,9,10}n1
