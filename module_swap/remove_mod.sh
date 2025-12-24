#!/bin/sh

echo 'rmmod kswap ...'
sudo modprobe -r -v swap
#make clean
echo 'kswap removed'
