#!/bin/bash
while true
do
	su - pi -c 'python /home/pi/remote-access-tunnelling-dev/onsitedev_script.py -T -p'
	sleep 2
done
