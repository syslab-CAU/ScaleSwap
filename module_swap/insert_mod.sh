#!/bin/sh

make -j 64 &&
make install -j 64 &&
sudo modprobe -v swap
