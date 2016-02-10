#!/usr/bin/python

# -*- coding: utf-8 -*-

#from __future__ import print_function

import os
import sys
import socket
import struct

import argparse

import logging
import logging.handlers

import subprocess

progname = os.path.basename(sys.argv[0])

logging.basicConfig()
logger = logging.getLogger(progname)

#~ if args.debug:
    #~ logger.setLevel(logging.DEBUG)
#~ else:
    #~ logger.setLevel(logging.INFO)

logger.setLevel(logging.DEBUG)

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter("%(levelname)s %(asctime)s %(name)s:%(lineno)d %(message)s"))
logger.addHandler(handler)
logger.propagate = False

# These constants map to constants in the Linux kernel. These should be set according to the target...
RTMGRP_LINK=0x1
NLMSG_NOOP=0x1
NLMSG_ERROR=0x2
NLMSG_DONE=0x3
RTM_NEWLINK=0x10
RTM_DELLINK=0x11
IFLA_IFNAME=0x3
IFF_UP=0x1
IFF_BROADCAST=0x2
IFF_DEBUG=0x4
IFF_LOOPBACK=0x8
IFF_POINTOPOINT=0x10
IFF_RUNNING=0x40
IFF_NOARP=0x80
IFF_PROMISC=0x100
IFF_NOTRAILERS=0x20
IFF_ALLMULTI=0x200
IFF_MASTER=0x400
IFF_SLAVE=0x800
IFF_MULTICAST=0x1000
IFF_PORTSEL=0x2000
IFF_AUTOMEDIA=0x4000
IFF_DYNAMIC=0x8000
IFF_LOWER_UP=0x10000
IFF_DORMANT=0x20000
IFF_ECHO=0x40000

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
	printf("IFF_BROADCAST=0x%x\n", IFF_BROADCAST);
	printf("IFF_DEBUG=0x%x\n", IFF_DEBUG);
	printf("IFF_LOOPBACK=0x%x\n", IFF_LOOPBACK);
	printf("IFF_POINTOPOINT=0x%x\n", IFF_POINTOPOINT);
	printf("IFF_RUNNING=0x%x\n", IFF_RUNNING);
	printf("IFF_NOARP=0x%x\n", IFF_NOARP);
	printf("IFF_PROMISC=0x%x\n", IFF_PROMISC);
	printf("IFF_NOTRAILERS=0x%x\n", IFF_NOTRAILERS);
	printf("IFF_ALLMULTI=0x%x\n", IFF_ALLMULTI);
	printf("IFF_MASTER=0x%x\n", IFF_MASTER);
	printf("IFF_SLAVE=0x%x\n", IFF_SLAVE);
	printf("IFF_MULTICAST=0x%x\n", IFF_MULTICAST);
	printf("IFF_PORTSEL=0x%x\n", IFF_PORTSEL);
	printf("IFF_AUTOMEDIA=0x%x\n", IFF_AUTOMEDIA);
	printf("IFF_DYNAMIC=0x%x\n", IFF_DYNAMIC);
	printf("IFF_LOWER_UP=0x%x\n", IFF_LOWER_UP);
	printf("IFF_DORMANT=0x%x\n", IFF_DORMANT);
	printf("IFF_ECHO=0x%x\n", IFF_ECHO);
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

"""
\brief Waits until there is a new netlink event from the kernel and parse it
\param socket The socket.AF_NETLINK socket (in socket.SOCK_RAW mode, with socket.NETLINK_ROUTE filtering)
\return A tuple of 3 items: the first item is the message type (RTM_NEWLINK or RTM_DELLINK), the second is a boolean indicating if the physical carrier is up (or None if N/A), the third is the interface name as a string
\note This function may raise exception if NLMSG_ERROR is received
"""
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
            return (msg_type, None, None)
        
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
                l1_link = (flags & IFF_LOWER_UP) != 0
                return (msg_type, l1_link, rta_data)

def process_secondary_if_events(on_link_up_callback, on_link_down_callback, on_destroy_callback):
    # Create the netlink socket and bind to RTMGRP_LINK,
    s = socket.socket(socket.AF_NETLINK, socket.SOCK_RAW, socket.NETLINK_ROUTE)
    s.bind((os.getpid(), RTMGRP_LINK))

    while True:
        (if_event, link_status, ifname) = get_next_netlink_event(socket=s)
        if if_event == RTM_NEWLINK:
            if is_secondary_usb_if(ifname):
                if link_status:
                    if on_link_up_callback is not None:
                        on_link_up_callback(str(ifname))
                else:
                    if on_link_down_callback is not None:
                        on_link_down_callback(str(ifname))
        elif if_event == RTM_DELLINK:
            if on_destroy_callback is not None:
                on_destroy_callback(str(ifname))
        #~ else:
            #~ logger.warning('Unknown message')

class DhcpService:
    def __init__(self):
        self.ip_addr = '192.168.38.225'
        self.ip_netmask = '255.255.255.240'
        self.dhcp_range_start = '192.168.38.226'
        self.dhcp_range_end ='192.168.38.238'
        
class InterfaceHandler:
    def __init__(self, ifname, watcher):
        self.ifname = ifname
        self.parent_watcher = watcher
        self.link = False
        self.dnsmasq_pid_file = '/var/run/secondary-if-dnsmasq.' + ifname + '.pid'
        self.dnsmasq_proc = None
        self.dhcp_subnet = None
        
    def set_link_up(self):
        if not self.link:
            self.link = True
            print('Link is going up for ' + self.ifname)
            try:
                self.dhcp_subnet = self.parent_watcher.allocate_ip_subnet()
                logger.debug('Using IP address ' + str(self.dhcp_subnet.ip_addr) + ' on interface ' + self.ifname)
                cmd = ['ifconfig', self.ifname, str(self.dhcp_subnet.ip_addr), 'netmask', str(self.dhcp_subnet.ip_netmask)]
                subprocess.check_call(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
                logger.debug('Distributing range ' + str(self.dhcp_subnet.dhcp_range_start) + '-' + str(self.dhcp_subnet.dhcp_range_end) + ' on interface ' + self.ifname)
                cmd = ['dnsmasq', '-i', self.ifname, '-u', 'dnsmasq', '-k', '--leasefile-ro', '--dhcp-range=interface:' + self.ifname + ',' + str(self.dhcp_subnet.dhcp_range_start) + ',' + str(self.dhcp_subnet.dhcp_range_end) + ',30', '--port=0', '--dhcp-authoritative', '--log-dhcp', '-x', self.dnsmasq_pid_file]
                subprocess.Popen(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            except:
                logger.error('Could not get a subnet to distribute')
                raise
        
    def set_link_down(self):
        if self.link:
            print('Link is going down for ' + self.ifname)
            if self.dnsmasq_proc is not None:
                logger.debug('Withdrawing all DHCP service configuration on interface ' + self.ifname)
                if not self.dnsmasq_proc.poll():
                    logger.warn('Subprocess dnsmasq for interface ' + ifname + ' died unexpectedly')
                else:
                    self.dnsmasq_proc.terminate()
                os.unlink(self.dnsmasq_pid_file)
                self.dnsmasq_proc = None
                cmd = ['ifconfig', self.ifname, '0.0.0.0']
                subprocess.check_call(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            if self.dhcp_subnet is not None:
                self.parent_watcher.release_ip_subnet(self.dhcp_subnet)
        
        self.link =  False
        
    def destroy(self):
        print('Interface ' + self.ifname + ' is being destroyed... performing cleanup')
        self.set_link_down()

class InterfacesWatcher:
    def __init__(self):
        self._secondary_if_dict = {}
        self._ip_subnet_allocated = None
        
    def if_link_up(self, ifname):
        if_handler = None
        try:
            if_handler = self._secondary_if_dict[ifname] # Check if this interface is already known
        except KeyError:
            print('Creating handler for interface ' + ifname)
            self._secondary_if_dict[ifname] = InterfaceHandler(ifname, self)
            if_handler = self._secondary_if_dict[ifname]
        if_handler.set_link_up()
        
    def if_link_down(self, ifname):
        if_handler = None
        try:
            if_handler = self._secondary_if_dict[ifname] # Check if this interface is already known
        except KeyError:
            print('Creating handler for interface ' + ifname)
            self._secondary_if_dict[ifname] = InterfaceHandler(ifname, self)
            if_handler = self._secondary_if_dict[ifname]
        if_handler.set_link_down()
    
    def if_destroyed(self, ifname):
        try:
            if_handler = self._secondary_if_dict[ifname] # Check if this interface is already known
            if_handler.destroy()
            del self._secondary_if_dict[ifname]
        except KeyError:
            pass
            
    def allocate_ip_subnet(self):
        if self._ip_subnet_allocated:
            raise Exception('DualSecondarySubnetNotSupported')
        else:
            self._ip_subnet_allocated = DhcpService()
            return self._ip_subnet_allocated

    def release_ip_subnet(self, ip_subnet):
        if ip_subnet != self._ip_subnet_allocated:
            raise Exception('UnknownSubnet')
        else:
            self._ip_subnet_allocated = None

if __name__ == '__main__':
    ifW = InterfacesWatcher()
    process_secondary_if_events(ifW.if_link_up, ifW.if_link_down, ifW.if_destroyed) # Run main loop