for dev in /dev/nvme*n1; do
    echo "Device: $dev"
    sudo nvme smart-log "$dev" | grep -i temperature
    echo "-------------------------"
done

