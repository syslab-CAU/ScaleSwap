#!/bin/bash

MODEL_NAME=$1

for device in /sys/block/*; do
	if [ -f "$device/device/model" ]; then
		model=$(cat "$device/device/model")
		if [[ $model = *"$MODEL_NAME"* ]]; then
			dev_name="/dev/$(basename $device)"
			echo "${cnt}: ${dev_name}"

			smartctl -a ${dev_name} | grep "Temperature Sensor"
		fi
	fi
done
