#!/bin/bash

while true
do
	su - pi -c 'python /home/pi/tunnelling-dev-scripts/onsitedev_script.py -T'
	sleep 2
done