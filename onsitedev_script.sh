#!/bin/bash
while true
do
	su - pi -c 'python /home/pi/tunnelling-dev-scripts/onsitedev_script.py -T -p -u rpi1108'
	sleep 2
done
