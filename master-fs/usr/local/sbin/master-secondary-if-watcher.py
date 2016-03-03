#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import sys
import socket
import struct

import ipaddr

import argparse

import re

import threading

import gobject
import dbus
import dbus.service
import dbus.mainloop.glib

import logging
import logging.handlers

import subprocess

import atexit

import glob

progname = os.path.basename(sys.argv[0])

ifW = None	# Global interface watcher object (used for cleanup)

logger = None

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

if __name__ == '__main__':
    def cleanup_at_exit():
        """
        Called when this program is terminated, to release the lock
        """
        
        global ifW
        
        if ifW:
            if logger: logger.info('Cleaning up at exit')
            if ifW._secondary_if and ifW._secondary_if.ifname:
                if logger: logger.debug('De-configuring interface ' + ifW._secondary_if.ifname)
                ifW.if_destroyed(ifW._secondary_if.ifname)

def list_all_sys_net_if():
    """
    List the machine's network interfaces and return their name in a list of strings
    \return A list of network interfaces (strings)
    """
    sys_net_path = glob.glob('/sys/class/net/*')
    # Now remove the /sys/class/net prefix, keep only the interface name
    p = re.compile('^/sys/class/net/')
    result = [ p.sub('', s) for s in sys_net_path ]
    
    return result

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

def is_if_up(ifname):
    """
    \brief Check a network interface's link status
    \param ifname The network interface name
    \return True if the network interface'link is up, False otherwise
    """
    with open('/sys/class/net/' + ifname + '/carrier', 'r') as f:
            status = f.readline()
            return (status == '1')

def process_existing_secondary_if(on_link_up_callback, on_link_down_callback):
    """
    \brief Lists currently existing secondary interfaces and run a callback on each of them
    \param on_link_up_callback Function to run on network interfaces with a link up
    \param on_link_down_callback Function to run on network interfaces with a link down
    """
    # Fetch the secondary network interfaces
    secondary_usb_ifs = filter(is_secondary_usb_if, list_all_sys_net_if())
    logger.debug('Secondary network interfaces detected at startup: ' +  str(secondary_usb_ifs))
    for net_if in secondary_usb_ifs:
        if is_if_up(net_if):
            on_link_up_callback(str(net_if))
        else:
            on_link_down_callback(str(net_if))

def get_next_netlink_event(socket):
    """
    \brief Waits until there is a new netlink event from the kernel and parse it
    \param socket The socket.AF_NETLINK socket (in socket.SOCK_RAW mode, with socket.NETLINK_ROUTE filtering)
    \return A tuple of 3 items: the first item is the message type (RTM_NEWLINK or RTM_DELLINK), the second is a boolean indicating if the physical carrier is up (or None if N/A), the third is the interface name as a string
    \note This function may raise exception if NLMSG_ERROR is received
    """
    
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
    """
    \brief Watches creation/destruction events on secondary network interfaces (using Linux netlink) interfaces and run a callback for each event
    \param on_link_up_callback Function to run on network interfaces with a link up
    \param on_link_down_callback Function to run on network interfaces with a link down
    \param on_destroy_callback Function to run on network interfaces that are being destroyed
    """
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
    def __init__(self, ip_addr, ip_prefix):
        self.ip_network = ipaddr.IPNetwork(str(ip_addr) + '/' + str(ip_prefix))
        if logger: logger.debug('Using secondary IP range ' + str(self.ip_network))
        self.ip_addr = self.ip_network.ip
        self.ip_netmask = self.ip_network.netmask
        self.dhcp_range_start = self.ip_addr + 1
        self.dhcp_range_end = self.ip_network.broadcast - 1
        if self.dhcp_range_start < self.dhcp_range_end: # Not enough IP addresses in range... raise an exception
            self.dhcp_range_size = int(self.dhcp_range_end) - int(self.dhcp_range_start) + 1    # Boundaries are included (start accounts for 1 more)
        else:
            raise Exception('InvalidDHCPRange')
        
class InterfaceHandler:
    """Class representing one secondary network interface
    """
    def __init__(self, ifname, watcher, if_dump_filename = None, deconfig_callback = None, config_callback = None):
        """\brief Generate an object representing a new secondary network interface
        \param ifname The network interface OS name (eg: 'eth1')
        \param deconfig_callback A function to run when this network interface is not usable anymore (it goes down, it is suppressed). This function will be invoked with the ifname as only argument
        \param config_callback A function to run when this network interface starts to be usable anymore (it goes up). This function will be invoked with the ifname as only argument
        """ 
        self.ifname = ifname
        self.parent_watcher = watcher
        self.link = False
        self.dnsmasq_pid_file = '/var/run/secondary-if-dnsmasq.' + ifname + '.pid'
        self.dnsmasq_proc = None
        self.dhcp_subnet = None
        self.if_dump_filename = if_dump_filename
        self.config_callback = config_callback
        self.deconfig_callback = deconfig_callback
        if logger: logger.debug('Discovered new interface ' + ifname)
    
    def set_link_up(self):
        if not self.link:
            try:
                self.config_callback(self.ifname)
            except:
                pass
            self.link = True
            if logger: logger.info('Link is going up for ' + self.ifname)
            try:
                self.dhcp_subnet = self.parent_watcher.allocate_ip_subnet()
                if logger: logger.debug('Using IP address ' + str(self.dhcp_subnet.ip_addr) + ' on interface ' + self.ifname)
                cmd = ['ifconfig', self.ifname, str(self.dhcp_subnet.ip_addr), 'netmask', str(self.dhcp_subnet.ip_netmask)]
                subprocess.check_call(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
                try:
                    with open(self.if_dump_filename, 'w+') as f:
                        f.write(self.ifname + '\n')
                except OSError:
                    pass # Ignore any error while removing the if dump file
                if logger: logger.debug('Distributing range ' + str(self.dhcp_subnet.dhcp_range_start) + '-' + str(self.dhcp_subnet.dhcp_range_end) + ' (' + str(self.dhcp_subnet.dhcp_range_size) + ' IP addresses) on interface ' + self.ifname)
                cmd = ['dnsmasq', '-i', self.ifname, '-u', 'dnsmasq', '-k', '--leasefile-ro', '--dhcp-range=interface:' + self.ifname + ',' + str(self.dhcp_subnet.dhcp_range_start) + ',' + str(self.dhcp_subnet.dhcp_range_end) + ',30', '--port=0', '--dhcp-authoritative', '--log-dhcp', '-x', self.dnsmasq_pid_file]
                self.dnsmasq_proc = subprocess.Popen(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
            except DhcpRangeAllocationError:
                raise
    
    def set_link_down(self):
        if self.link:
            try:
                self.deconfig_callback(self.ifname)
            except:
                pass
            if logger: logger.info('Link is going down for ' + self.ifname)
            if self.dnsmasq_proc is not None:
                if logger: logger.debug('Withdrawing all DHCP service configuration on interface ' + self.ifname)
                dnsmasq_exitcode = self.dnsmasq_proc.poll()
                if dnsmasq_exitcode is not None:
                    if logger: logger.warn('Subprocess dnsmasq for interface ' + self.ifname + ' already died unexpectedly with exit code ' + str(dnsmasq_exitcode))
                else:
                    self.dnsmasq_proc.terminate()
                os.unlink(self.dnsmasq_pid_file)
                self.dnsmasq_proc = None
                cmd = ['ifconfig', self.ifname, '0.0.0.0']
                subprocess.call(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)   # ifconfig may fail if network interface does not exist anymore
            if self.dhcp_subnet is not None:
                self.parent_watcher.release_ip_subnet(self.dhcp_subnet)
        
        try:
            os.unlink(self.if_dump_filename)
        except OSError:
            pass # Ignore any error while removing the if dump file
        
        self.link =  False
        
    def is_configured(self):
        return self.link
        
    def destroy(self):
        if logger: logger.debug('Interface ' + self.ifname + ' is being destroyed... performing cleanup')
        self.set_link_down()

class DhcpRangeAllocationError(Exception):
    pass

class InterfacesWatcher:
    def __init__(self, ip_addr, ip_prefix, if_dump_filename = None):
        self.ip_addr = ip_addr
        self.ip_prefix = ip_prefix
        self._secondary_if = None
        self._secondary_if_mutex = threading.Lock()	# Mutex protecting reads/writes to self._secondary_if
        self._ip_subnet_allocated = None
        self.if_dump_filename = if_dump_filename
        self.interface_destroy_callback = None	# Callback invoked when current secondary interface is going down
        self.interface_add_callback = None	# Callback invoked when a new secondary interface is going up
    
    def set_active_if(self, ifname):
        with self._secondary_if_mutex:
            if self._secondary_if is not None:
                if self._secondary_if.ifname != ifname: # This interface is a different one from the previous active one
                    self._secondary_if.destroy()
                    self._secondary_if = None
            if self._secondary_if is None:
                #~ print('Creating handler for interface ' + ifname)
                self._secondary_if = InterfaceHandler(ifname, self, self.if_dump_filename, deconfig_callback=self.interface_destroy_callback, config_callback=self.interface_add_callback)
    
    def if_link_up(self, ifname):
        if logger: logger.debug('Interface ' + ifname + ' changed to status link up')
        self.set_active_if(ifname)
        with self._secondary_if_mutex:
            self._secondary_if.set_link_up()
        
    def if_link_down(self, ifname):
        if logger: logger.debug('Interface ' + ifname + ' changed to status link down')
        self.set_active_if(ifname)
        with self._secondary_if_mutex:
            self._secondary_if.set_link_down()
    
    def if_destroyed(self, ifname):
        if self._secondary_if is not None:
            if self._secondary_if.ifname == ifname: # This interface is a different one from the previous active one
                with self._secondary_if_mutex:
                    self._secondary_if.destroy()
                    self._secondary_if = None
    
    def allocate_ip_subnet(self):
        if self._ip_subnet_allocated:
            raise DhcpRangeAllocationError('DualSecondarySubnetNotSupported')
        else:
            self._ip_subnet_allocated = DhcpService(ip_addr=self.ip_addr, ip_prefix=self.ip_prefix)
            return self._ip_subnet_allocated

    def release_ip_subnet(self, ip_subnet):
        if ip_subnet != self._ip_subnet_allocated:
            raise Exception('UnknownSubnet')
        else:
            self._ip_subnet_allocated = None
            
    def get_last_ifname(self):
        with self._secondary_if_mutex:
            if self._secondary_if is not None and self._secondary_if.is_configured():
                return self._secondary_if.ifname
            else:
                return ''

class SecondaryIfWatcherDBusService(dbus.service.Object):
    """ D-Bus requests responder
    """
    
    DBUS_NAME = 'com.legrandelectric.RemoteAccess.SecondaryIfWatcher'	# The name of bus we are creating in D-Bus
    DBUS_OBJECT_ROOT = '/com/legrandelectric/RemoteAccess/SecondaryIfWatcher'	# The D-Bus object on which we will commnunicate 
    DBUS_SERVICE_INTERFACE = 'com.legrandelectric.RemoteAccess.SecondaryIfWatcher'	# The name of the D-Bus service under which we will perform input/output on D-Bus

    def __init__(self, interface_watcher, conn, dbus_object_path = DBUS_OBJECT_ROOT, **kwargs):
        """ Instanciate a new SecondaryIfWatcherDBusService object handling responses to D-Bus
        \param conn A D-Bus connection object
        \param dbus_loop A main loop to use to process D-Bus request/signals
        \param dbus_object_path The path of the object to handle on D-Bus
        """
        # Note: **kwargs is here to make this contructor more generic (it will however force args to be named, but this is anyway good practice) and is a step towards efficient mutliple-inheritance with Python new-style-classes
        dbus.service.Object.__init__(self, conn=conn, object_path=dbus_object_path)
        self.interface_watcher = interface_watcher
        interface_watcher.interface_destroy_callback = self.InterfaceRemoved	# Request interface_watcher object to call InterfaceRemoved (in order to send a D-Bus signal when secondary network interface is going down)
        interface_watcher.interface_add_callback = self.InterfaceAdded	# Request interface_watcher object to call InterfaceAdded (in order to send a D-Bus signal when secondary network interface is going up)
        logger.debug('Registered binding with D-Bus object PATH: ' + str(dbus_object_path))
    
    # D-Bus-related methods
    @dbus.service.method(dbus_interface = DBUS_SERVICE_INTERFACE, in_signature='', out_signature='s')
    def GetInterface(self):
        """ Get the currently active secondary interface for this master device
        \return The name of the current secondary network interface (USB to Ethernet dongle) or '' if None
        """
        ifname = self.interface_watcher.get_last_ifname()
        if ifname is None:
            ifname = ''
        logger.debug('Replying "' + ifname + '" to D-Bus request GetInterface')
        return ifname
       
    @dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
    def InterfaceRemoved(self, interface_name):
        """
        D-Bus decorated method to send the "InterfaceRemoved" signal
        """
        pass
    
    @dbus.service.signal(dbus_interface = DBUS_SERVICE_INTERFACE)
    def InterfaceAdded(self, interface_name):
        """
        D-Bus decorated method to send the "InterfaceAdded" signal
        """
        pass

if __name__ == '__main__':
    EXTREMITY_IF_FILENAME = '/var/run/extremity_if'
    
    # Parse arguments

    parser = argparse.ArgumentParser(description="This program watches all network interfaces for removable USB to Ethernet adapters. \
When it finds one, it automatically sets it up and distributres IP addresses on this interface.", prog=progname)
    parser.add_argument('-d', '--debug', action='store_true', help='display debug info', default=False)
    parser.add_argument('-D', '--dbus-responder', action='store_true', dest='dbus_responder', help='enable the D-Bus responder', default=False)
    parser.add_argument('-I', '--ip-addr', dest='ip_addr', type=str, help='Use the specified IP address and prefix for the USB interface in the CIDR notation', default='192.168.38.225/29')
    
    args = parser.parse_args()
    
    # Setup logging
    logging.basicConfig()
    if not args.debug:
        progname = progname.split('.')[0]   # Remove .py extension when logging in non-debug mode
    
    logger = logging.getLogger(progname)

    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    if args.debug:
        handler = logging.StreamHandler()
    else:
        handler = logging.handlers.WatchedFileHandler('/var/log' + progname + '.log')
    
    handler.setFormatter(logging.Formatter("%(levelname)s %(asctime)s %(name)s:%(lineno)d %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    
    if os.getuid() != 0:
        logger.error('This script should be run as root as if will run ifconfig and DHCP service which require root privileges')
        raise Exception('RootRequired')
    
    ip_addr = None
    ip_netmask = None
    match = re.match(r'^([0-9]+\.[0-9]+\.[0-9]+\.[0-9]+)/([0-9]+)$', args.ip_addr)
    if match:
        ip_addr = match.group(1)
        ip_prefix = int(match.group(2))
        if ip_prefix<8 or ip_prefix>30:
            raise Exeption('InvalidPrefix:' + ip_prefix)
    else:
        logger.error('Invalid IP address or netmask: ' + args.ip_addr)
        raise Exception('InvalidIPParams')
    
    atexit.register(cleanup_at_exit)
    ifW = InterfacesWatcher(ip_addr, ip_prefix, if_dump_filename=EXTREMITY_IF_FILENAME) # Start watching, dump the new interfaces activated into file EXTREMITY_IF_FILENAME (for masterdev_script to use)
    
    if args.dbus_responder:
        dbus.mainloop.glib.DBusGMainLoop(set_as_default=True) # Use Glib's mainloop as the default loop for all subsequent code
        
        # Prepare D-Bus environment
        system_bus = dbus.SystemBus(private=True)
        
        logger.debug('Going to register D-Bus listener')
        name = dbus.service.BusName(SecondaryIfWatcherDBusService.DBUS_NAME, system_bus) # Publish the name to the D-Bus so that clients can see us
        
        # Allow secondary threads to run during the mainloop
        gobject.threads_init() # Allow the mainloop to run as an independent thread
        dbus.mainloop.glib.threads_init()
        
        dbus_loop = gobject.MainLoop()
        
        # Run the D-Bus thread
        ifwatcher_dbus_handler = SecondaryIfWatcherDBusService(conn=system_bus, dbus_loop=dbus_loop, interface_watcher=ifW)
        dbus_loop_thread = threading.Thread(target=dbus_loop.run)
        dbus_loop_thread.setDaemon(True)	# dbus loop should be forced to terminate when main program exits
        dbus_loop_thread.start()
    
    process_existing_secondary_if(ifW.if_link_up, ifW.if_link_down) # Discover interfaces that already exist
    process_secondary_if_events(ifW.if_link_up, ifW.if_link_down, ifW.if_destroyed) # Run main loop
