#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import paramiko
import pexpect
import sys

import logging

import tempfile

import ipaddr

import socket, struct, fcntl    # For get_ip()


class TunnellingDev(object):
    """ Class representing a tunnelling device
    A tunnelling device is a abstract device gathering client devices or server devices
    """
    
    PROTO_RDV_SERVER = '10.10.8.11'
    
    def __init__(self, username, logger, key_filename = None):
        """ Constructor
        \param username The username to use with ssh to connect to the RDV server
        \param key_filename A file containing the private key for key-based ssh authentication
        \param logger A logging.Logger to use for log messages
        """
        self._rdv_server = TunnellingDev.PROTO_RDV_SERVER
        #self._ssh_connection = None
        self._ssh_username = username
        self._ssh_key_filename = key_filename
        self._exp = None
        self._prompt = '1001[$] '
        self.logger = logger
        self.exp_logfile = None # This attribute, if not None, will contain a tempfile.TemporaryFile object where all expect session is stored
    
    def _get_ip_network(self, iface = 'eth0'):
        """ Get the IPv4 address of the specified interface
        \param iface The interface to check
        \return An ipaddr.IPv4Network object containing the IP address + netmask
        """
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sockfd = sock.fileno()
        SIOCGIFADDR = 0x8915
        SIOCGIFNETMASK = 0x891b
        
        ifreq = struct.pack('16sH14s', iface, socket.AF_INET, '\x00'*14)
        ip = None
        netmask = None
        
        try:
            res_ip = fcntl.ioctl(sockfd, SIOCGIFADDR, ifreq)
            ip = struct.unpack('16sH2x4s8x', res_ip)[2]
            ip = socket.inet_ntoa(ip)
            res_netmask = fcntl.ioctl(sockfd, SIOCGIFNETMASK, ifreq)
            netmask = struct.unpack('16sH2x4s8x', res_netmask)[2]
            netmask = socket.inet_ntoa(netmask)
        except:
            return None
        
        return ipaddr.IPv4Network(str(ip) + '/' + str(netmask)) 
    
    def catch_prompt(self, timeout = 2):
        """ Wait for a remote prompt to appear
        
        Note: the expected prompt is stored in attribute self._prompt
        This method will raise exceptions in case of failure
        \param timeout How long (in secs) are we ready to wait for the prompt
        """
        index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, self._prompt], timeout=timeout)
        if index == 0:    # Timeout
            self.logger.error("Could not wake up terminal")
            raise('ConnectionError')
        elif index == 1:    # EOF
            self.logger.error("Remote connection closed")
            raise('ConnectionError')
        elif index == 2:    # linux_prompt_catchall_regexp a second time
            pass    # We are now sure we are logged in now
    
    def rdv_server_connect(self):
        """ Initiate the ssh connection to the RDV server
        This method will raise exceptions in case of failure
        """
        
        if not self._ssh_key_filename is None:
            logger.error('Providing a ssh key filename is not yet supported')
            raise('SSHKeyFilenameNotSupported')
        self._exp = pexpect.spawn('ssh', ['-oUserKnownHostsFile=/dev/null', '-oStrictHostKeyChecking=no', self._ssh_username + '@' + self._rdv_server])
        supposedly_logged_in = False
        surely_logged_in = False
        
        index = self._exp.expect([pexpect.TIMEOUT, 'Permission denied', self._ssh_username + '@.*password: ', self._prompt], timeout=4)
        if self.logger.isEnabledFor(logging.DEBUG):
            self._exp.logfile = sys.stdout    # Log to stdout in DEBUG mode
        else:
            self.exp_logfile = tempfile.TemporaryFile() # Create a temprary file to store expect session
            self._exp.logfile = self.exp_logfile
        
        if index == 0:
            self.logger.error("Remote connection closed")
            raise('ConnectionError')
        elif index == 1:
            self.logger.error("Permission denied, public key authentication rejected")
            raise Exception('PublicKeyNotAccepted')
        elif index == 2:
            self.logger.error("Username/password required, public key authentication rejected")
            raise Exception('PublicKeyNotAccepted')
        elif index == 3:    # linux_prompt_catchall_regexp
            pass    # We are probably logged in
        
        # We think we have been logged in... try to hit return and check if we have a prompt once more
        self._exp.send('\r')    # Wake up terminal (we send a carriage return to find out if we are logged in (in a shell) or not (in the prompt))
        self.catch_prompt()
        self.logger.debug('Logged in to tundev shell')
        # Note: rule for all methods is to always end up with a fresh prompt catched, ready to type new commands
            
#     def rdv_server_connect(self):
#         """ Initiate the ssh connection to the RDV server """
#         self._ssh_connection = paramiko.SSHClient()
#         self._ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # FIXME: really check the server certificate
#         self._ssh_connection.connect(self._rdv_server, username=self._ssh_username, key_filename=self._ssh_key_filename)

    def rdv_server_disconnect(self):
        """ Close the ssh connection to the RDV server if it is up """
        if not self._exp is None:
            self._exp.send('logout\r')
            self._exp.close()
            self._exp =  None
    
    def run_command(self, command, prompt_timeout = 2):
        """ Run a tundev shell command and return the output as a string
        \param command A string containing the tundev shell command to execute (without the ending carriage return)
        \param prompt_timeout A int containing a timeout for the new prompt to appear after having typed the command
        \return The output (mixed stout and stderr) that we got before the new prompt
        """
        if not self._exp is None:
            #self._exp.buffer = ''
            #self._exp.before = ''   # Eat all preceeding input
            self._exp.send(command + '\r')
            self.catch_prompt(timeout=prompt_timeout)
            output = str(self._exp.before)
            # Now, in output, we might have the whole command included (most terminals do echo what is typed in)
            if output.startswith(command):
                output = output[len(command):]
                if output.startswith('\r\n'):   # Get rid of MSDOS-style carriage returns
                    output = output[2:]
                elif output.startswith('\n'):   # Get rid of UNIX-style carriage returns
                    output = output[1:]
                    
            #print(' '.join(x.encode('hex') for x in output))
            #print('Got command result is: "' + output + '"\n\n')
            return output
        else:
            raise('NotConnected')
        
    def _strip_trailing_cr_from(self, string):
        """ Removes the trailing carriage return from the string provided as argument
        \param string The input string
        \return The string with the last carriage returns stripped
        """
        if string.endswith('\r\n'):   # Get rid of MSDOS-style carriage returns at the end of the string
            string = string[:-2]
        elif string.endswith('\n'):   # Get rid of UNIX-style carriage returns at the end of the string
            string = string[:-1]
        return string
    
    def run_set_tunnelling_dev_lan_ip_address(self, ip):
        """ Run the command set_tunnelling_dev_lan_ip_address on the remote tundev shell
        \param ip an ipaddr.IPv4Network object or a string containing the IP address and prefix using the CIDR notation, to communicate to the RDV server
        """
        self.run_command('set_tunnelling_dev_lan_ip_address ' + str(ip), 2)
    
    def send_lan_ip_address_for_iface(self, iface):
        """ Send the IP addressing for the interface iface to the remote tundev shell
        \param iface The network interface for which we will extract the IP address
        """
        self.run_set_tunnelling_dev_lan_ip_address(self._get_ip_network(iface))

    def run_get_tunnel_mode(self):
        """ Run the command get_tunnel_mode on the remote tundev shell
        \return The tunnel mode as a string
        """
        return self._strip_trailing_cr_from(self.run_command('get_tunnel_mode', 2))
    
    def run_set_tunnelling_dev_uplink_type(self, uplink_type):
        """ Run the command set_tunnelling_dev_uplink_type on the remote tundev shell
        \param uplink_type The uplink type as a string (usual values 'lan' or '3g')
        """
        self.run_command('set_tunnelling_dev_uplink_type ' + str(uplink_type), 2)
    