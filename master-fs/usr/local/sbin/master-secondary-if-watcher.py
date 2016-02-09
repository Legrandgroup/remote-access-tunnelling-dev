#!/usr/bin/python

# -*- coding: utf-8 -*-

#from __future__ import print_function

import os
import socket
import struct

# These constants map to constants in the Linux kernel. These should be set according to the target...
RTMGRP_LINK=0x1
NLMSG_NOOP=0x1
NLMSG_ERROR=0x2
NLMSG_DONE=0x3
RTM_NEWLINK=0x10
RTM_DELLINK=0x11
IFLA_IFNAME=0x3
IFF_UP=0x1

#In order to adapt these values to your platform, you will have to compile and run the following C code, and paste the result into the section above
"""
#include <asm/types.h>
#include <sys/socket.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <stdio.h>

int main (int arvc, char *argv[]) {
	printf("RTMGRP_LINK=0x%x\n", RTMGRP_LINK);
	printf("NLMSG_NOOP=0x%x\n", NLMSG_NOOP);
	printf("NLMSG_ERROR=0x%x\n", NLMSG_ERROR);
	printf("NLMSG_DONE=0x%x\n", NLMSG_DONE);
	printf("RTM_NEWLINK=0x%x\n", RTM_NEWLINK);
	printf("RTM_DELLINK=0x%x\n", RTM_DELLINK);
	printf("IFLA_IFNAME=0x%x\n", IFLA_IFNAME);
	printf("IFF_UP=0x%x\n", IFF_UP);
	return 0;
}
"""

def is_secondary_usb_if(ifname):
    
    if ifname == 'eth0':    # Never accept eth0 as a secondary interface
        return False
    
    sys_net_path = '/sys/class/net/' + str(ifname)
    try:
        if_name = os.path.basename(sys_net_path)
        if not os.path.exists(sys_net_path + '/wireless'):	# Skip wireless interfaces
            real_path = os.path.realpath(sys_net_path + '/device/subsystem')
            if os.path.exists(real_path):	# Keep only USB-connected interfaces
                if real_path == '/sys/bus/usb':
                    return True
    except OSError:
        pass
    
    return False

def get_next_netlink_event(socket):
    
    while True:
        data = socket.recv(65535)
        nlmsghdr = data[:16]
        data = data[16:]    # Skip the first 16 bytes that we have processed
        msg_len, msg_type, flags, seq, pid = struct.unpack("=LHHLL", nlmsghdr)

        if msg_type == NLMSG_NOOP:
            continue
        if msg_type == NLMSG_ERROR:
            raise Exception('NLMSG_ERROR')

        #~ print('msg_type=' + str(msg_type) + ': ' + ' '.join('{:02x}'.format(ord(c)) for c in nlmsghdr))
        
        # We fundamentally only care about NEWLINK messages in this version.
        if msg_type != RTM_NEWLINK and msg_type != RTM_DELLINK:
            return (msg_type, '')
        
        ifinfomsg = data[:16]
        rtattr_list = data[16:]    # Skip the ifinfomsg (16 bytes) that we have processed

        family, _, if_type, index, flags, change = struct.unpack("=BBHiII", ifinfomsg)
        #~ print('ifinfomsg: ' + ' '.join('{:02x}'.format(ord(c)) for c in ifinfomsg))
        #~ print('family=%d, if_type=%d, index=%d, flags=0x%x, change=%d' % (family, if_type, index, flags, change))
        
        if msg_type == RTM_NEWLINK and not (flags & IFF_UP):    # Do not care about new interfaces that are not up (yet)
            continue

        #~ print('rtattr_list: ' + ' '.join('{:02x}'.format(ord(c)) for c in rtattr_list))
        remaining = msg_len - 32    # We have eaten twice 16 bytes so far

        while remaining:    # Now parse the rtattr list
            #~ print('Parsing: ' + ' '.join('{:02x}'.format(ord(c)) for c in rtattr_list[:4]))
            rta_len, rta_type = struct.unpack("=HH", rtattr_list[:4])

            # This check comes from RTA_OK, and terminates a string of routing
            # attributes.
            if rta_len < 4:
                break

            rta_data = rtattr_list[4:rta_len]

            increment = (rta_len + 4 - 1) & ~(4 - 1)
            rtattr_list = rtattr_list[increment:]
            remaining -= increment
            
            if rta_type == IFLA_IFNAME: # We are getting to the interface name part of the netlink message... this is what we are looking for
                rta_data = rta_data.rstrip('\x00')  # Interface name strings are usually NULL terminated
                return (msg_type, rta_data)

# Create the netlink socket and bind to RTMGRP_LINK,
s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
s.bind((os.getpid(), RTMGRP_LINK))

while True:
    (status, ifname) = get_next_netlink_event(socket=s)
    print('ifname="' + ifname + '"')
    if is_secondary_usb_if(ifname):
        if status == RTM_NEWLINK:
            print('New info on enabled interface ' + str(ifname))
        elif status == RTM_DELLINK:
            print('Disabled interface ' + str(ifname))
        else:
            print('Unknown message')
