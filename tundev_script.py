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

import os
import subprocess

from pythonvtunlib import client_vtun_tunnel

class TunnellingDev(object):
    """ Class representing a tunnelling device
    A tunnelling device is a abstract device gathering client devices or server devices
    """
    
    PROTO_RDV_SERVER = '10.10.8.11'
    SSH_ESCAPE_SHELL_PROMPT = 'ssh> '
                
    def __init__(self, username, logger, key_filename = None, prompt = None):
        """ Constructor
        \param username The username to use with ssh to connect to the RDV server
        \param logger A logging.Logger to use for log messages
        \param key_filename A file containing the private key for key-based ssh authentication
        \param prompt The expected prompt (if None, will be built from the username) 
        """
        self._rdv_server = TunnellingDev.PROTO_RDV_SERVER
        #self._ssh_connection = None
        self._ssh_username = username
        self._ssh_key_filename = key_filename
        self._exp = None
        if prompt is None:
            self._prompt = username + '[$] '
        else:
            self._prompt = str(prompt)
        
        self.logger = logger
        self.exp_logfile = None # This attribute, if not None, will contain a tempfile.TemporaryFile object where all expect session is stored
        self.ssh_escape_shell_supported = None  # This attribute will be set to True if an escape ssh shell is supported on our ssh client
        self.ssh_l_supported = None # This attributes describes whether remote port forwarding is supported on the ssh session (ssh -L option)
        self.ssh_remote_tcp_port = None # This attribute contains the remote TCP port on which vtun is accessible on the remote machine (we will tunnel this into the existing ssh session) 
    
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
    
    def catch_prompt(self, timeout = 2, exception_on_cmd_syntax_error = False):
        """ Wait for a remote prompt to appear
        
        Note: the expected prompt is stored in attribute self._prompt
        This method will raise exceptions in case of failure
        \param timeout How long (in secs) are we ready to wait for the prompt
        """
        expect_list = [pexpect.TIMEOUT, pexpect.EOF]
        if exception_on_cmd_syntax_error:   # If we also need to catch syntax error messages...
            expect_list += ['[*][*][*] Unknown syntax:']
        expect_list += [self._prompt]
        
        index = self._exp.expect(expect_list, timeout=timeout)
        if index == 0:    # Timeout
            self.logger.error("Remote connection is frozen")
            raise Exception('SSHConnectionLost')
        elif index == 1:    # EOF
            self.logger.error("Remote connection closed")
            raise Exception('SSHConnectionLost')
        elif index == 2 and exception_on_cmd_syntax_error:
            raise Exception('TundevShellSyntaxError')
        else:
            if exception_on_cmd_syntax_error:
                index -= 1	# Remove the inserted syntax error regexp to have common test whatever the value of exception_on_cmd_syntax_error is (expected index should be 2 or 3 if exception)
            if index == 2:    # linux_prompt_catchall_regexp a second time
                pass    # We are now sure we are logged in now
            else:	# Something is wrong in the index returned
                raise Exception('WrongInternalExpIndex:' + str(index))
    
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
        
        index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, 'Permission denied', self._ssh_username + '@.*password: ', self._prompt], timeout=40)
        if self.logger.isEnabledFor(logging.DEBUG):
            self._exp.logfile = sys.stdout    # Log to stdout in DEBUG mode
        else:
            self.exp_logfile = tempfile.TemporaryFile() # Create a temprary file to store expect session
            self._exp.logfile = self.exp_logfile
        
        if index == 0 or index == 1:
            self.logger.error("Remote connection closed")
            session_output = str(self._exp.before) + str(self._exp.buffer)
            session_output = '|' + session_output.replace('\n', '\n|')  # Prefix the whole output with a | character so that dump is easily spotted
            if session_output.endswith('|'):    # Remove the last line that only contains a | character
                session_output = session_output[:-1]
            while session_output.endswith('|\n'):   # Get rid of the last empty line(s) that is/are present most of the time
                session_output = session_output[:-2]
            print('Failed to open remote ssh connection. Output was:\n' + session_output , file=sys.stderr)
            raise Exception('ConnectionError')
        elif index == 2:
            self.logger.error('Permission denied, public key authentication rejected on account ' + self._ssh_username)
            raise Exception('PublicKeyNotAccepted')
        elif index == 3:
            self.logger.error('Username/password required, public key authentication rejected on account ' + self._ssh_username)
            raise Exception('PublicKeyNotAccepted')
        elif index == 4:    # linux_prompt_catchall_regexp
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
            self.catch_prompt(timeout=prompt_timeout, exception_on_cmd_syntax_error=True)
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
    
    def _assert_ssh_escape_shell(self):
        """ Check if an ssh escape shell is available in the current ssh session
        
        Note: this check will only be performed once, and its result will then be cached and re-used for future calls to this method
        If this check fails, an exception will be raised, otherwise, self.ssh_escape_shell_supported will be set to True
        """
        if not self.ssh_escape_shell_supported:
            if not self._exp is None:
                self.run_command('echo Testing ssh escape shell')
                self._exp.send('~C')
                index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, TunnellingDev.SSH_ESCAPE_SHELL_PROMPT], timeout=2)
                if index == 0:    # Timeout
                    self.logger.error('Failed to get an ssh escape shell')
                    raise Exception('NoSSHEscapeShellAvailable')
                elif index == 1:    # EOF
                    self.logger.error('Remote connection closed')
                    raise Exception('SSHConnectionLost')
                elif index == 2:    # Got the ssh> escape shell prompt
                    self.logger.debug('Successfully entered an ssh escape shell')
                    self.ssh_escape_shell_supported = True
                    self._exp.send('help\r')
                    index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, '-L\[.*:\].*:.*:.*'], timeout=1)
                    if index == 0:    # Timeout
                        self.logger.warning('No remote port forwarding supported in this ssh session')
                        self.ssh_l_supported = False
                    elif index == 1:    # EOF
                        self.logger.error('Remote connection closed')
                        raise Exception('SSHConnectionLost')
                    elif index == 2:    # Got the -L option
                        self.logger.debug('Remote port forwarding is supported in this ssh session')
                        self.ssh_l_supported = True
                    self.run_command('echo ...done')
            else:
                raise('NotConnected')
            
    def ssh_port_forward(self, local_port, remote_port, hostname_target_on_remote = '127.0.0.1', bind_address = None):
        """ Sets a remote port forwarding on the current ssh session (equivalent to the ssh -L option, with the same arguments)
        
        If we are unable to perform the forward, we will raise an exception
        \param local_port The TCP port on the local machine that will be forwarded to the remote ssh host inside the ssh session
        \param remote_port The TCP port on the remote machine to which will be output the forwarded traffic
        \param hostname_target_on_remote An optional remote machine to which will be output the forwarded traffic (optional, by default this is the remote machine itself)
        \param bind_address The IP address on which to bind the listening (TCP) socket on the local machine (this is the socket that will listen on the \p local_port)
        """
        self._assert_ssh_escape_shell() # Make sure we check the escape shell and its capabilities
        if not self.ssh_l_supported:
            raise Exception('NoRemoteSSHForwardingSupported')
        if local_port is None:
            raise Exception('LocalPortIsMandatory')
        if remote_port is None:
            raise Exception('RemotePortIsMandatory')
        # ssh remote redirect command is -L[bind_address:]port:host:hostport
        ssh_redirect_command = '-L'
        if not bind_address is None:
            ssh_redirect_command += str(bind_address) + ':'
        
        ssh_redirect_command += str(local_port)
        ssh_redirect_command += ':'
        ssh_redirect_command += str(hostname_target_on_remote)
        ssh_redirect_command += ':'
        ssh_redirect_command += str(remote_port)
        
        self.logger.debug('Adding ssh redirect escape shell "' + ssh_redirect_command + '"')
        self.run_command('echo Adding ssh redirect escape shell "' + ssh_redirect_command + '"')
        self._exp.send('~C')
        index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, TunnellingDev.SSH_ESCAPE_SHELL_PROMPT], timeout=2)
        if index == 0:    # Timeout
            self.ssh_escape_shell_supported = False # Remember that ssh escape shell failed this time
            raise Exception('NoSSHEscapeShellAvailable')
        elif index == 1:    # EOF
            self.logger.error('Remote connection closed')
            raise Exception('SSHConnectionLost')
        elif index == 2:    # Got the ssh> escape shell prompt
            self.logger.debug('Entered in ssh escape shell CLI')
            self._exp.send(ssh_redirect_command + '\r') # Ask ssh port redirection to the remote session
            # Now, make sure ssh has applied the port redirection.
            # ssh escape shell could return us error string slike 'channel_setup_fwd_listener:'. This would happen if a zombie ssh connection remains, for example after having sent a SIGKILL to this python script while the tunnel was up
            # Note: Even when we get such errors, we will also get the message 'Forwarding port', so we must detect the error, not the false-positive confirmation
            index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, '(?i)channel_setup_fwd_listener.*cannot listen', '(?i)forwarding port', ], timeout=2)    # ?i allows us to perform case insensitive matching
            if index == 0:
                self.logger.warning('Could not get confirmation from ssh shell that forwarding was successful. Assuming everything is OK')
            elif index == 1:
                self.logger.error('Remote connection closed')
                raise Exception('SSHConnectionLost')
            elif index == 2:
                self.logger.error('SSH forwarding failed. Please check that no other service is using TCP port ' + str(local_port) + ' (with "lsof -i" or "fuser -n tcp ' + str(local_port) + '")')
                raise Exception('SSHForwardingFailed')
            elif index == 3:
                self.logger.debug('Got forwarding confirmation from ssh shell')
        
        self.run_command('echo ...done')    # Run a dummy command to make sure we got back to ssh shell
    
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

    def run_get_role(self):
        """ Run the command get_role on the remote tundev shell
        \return The role as a string
        """
        role = self._strip_trailing_cr_from(self.run_command('get_role', 2))
        if role == '':
            raise Exception('TundevShellSyntaxError')
    
    def run_get_tunnel_mode(self):
        """ Run the command get_tunnel_mode on the remote tundev shell
        \return The tunnel mode as a string
        """
        mode = self._strip_trailing_cr_from(self.run_command('get_tunnel_mode', 2))
        if mode == '':
            raise Exception('TundevShellSyntaxError')
    
    def run_set_tunnelling_dev_uplink_type(self, uplink_type):
        """ Run the command set_tunnelling_dev_uplink_type on the remote tundev shell
        \param uplink_type The uplink type as a string (usual values 'lan' or '3g')
        """
        self.run_command('set_tunnelling_dev_uplink_type ' + str(uplink_type), 2)
            
    def run_get_vtun_parameters(self):
        """ Run the command get_tunnel_mode on the remote tundev shell
        \return The vtun config output string returned by the RDV server
        """
        return self._strip_trailing_cr_from(self.run_command('get_vtun_parameters', 20))
    
    class ClientVtunTunnelConfig(object):
        """ Class representing a tunnelling device configuration as provided by the remote tundev shell command get_vtun_parameters
        This class is just a container around a python dict, with one method allowing to generate a pythonvtunlib.client_vtun_tunnel based on the parameters contained in the self.dict attribute  
        """
        def __init__(self, config_dict, tunnel_mode, tunnel_name, vtun_server_hostname, vtun_server_port, vtund_exec = None, vtund_use_sudo = False, vtun_connection_timeout = 20):
            """ Constructor
            \param dict A python dict to encapsulate into this object
            \param tunnel_mode The tunnel mode ('L2', 'L3' etc...)
            \param tunnel_name Name (in the vtund terminology) of the tunnel session
            \param vtun_server_hostname The hostname to connect to (the vtund server)
            \param vtun_server_port The TCP port to use when connecting to the vtund server  
            \param vtund_exec (optional) The PATH to the vtund binary
            \param vtund_use_sudo (optional) A boolean indicating whether the vtund_exec needs to be run via sudo to get root access (False by default)
            \param vtun_connection_timeout How many seconds we give for the tunnel establishment (20 by default)
            """
            self.config_dict = config_dict
            self.tunnel_mode = tunnel_mode
            self.tunnel_name = tunnel_name
            self.vtun_server_hostname = vtun_server_hostname
            self.vtun_server_port = vtun_server_port
            self.vtund_exec = vtund_exec
            self.vtund_use_sudo = vtund_use_sudo
            self.vtun_connection_timeout = vtun_connection_timeout
        
        def to_client_vtun_tunnel_object(self):
            """ Create a pythonvtunlib.client_vtun_tunnel object based on the configuration found in our self.dict attribute
        
            If the self.dict attribute does not have (enough) information to build a client tunnel, an exception will be raised
            \return The resulting pythonvtunlib.client_vtun_tunnel
            """
            try:
                tunnel_ip_prefix = str(self.config_dict['tunnel_ip_prefix'])
                tunnel_ip_network = str(self.config_dict['tunnel_ip_network'])
                if not tunnel_ip_prefix.startswith('/'):
                    tunnel_ip_network += '/'
                tunnel_ip_network += tunnel_ip_prefix
    
                return client_vtun_tunnel.ClientVtunTunnel(vtund_exec = self.vtund_exec,
                                                           vtund_use_sudo = self.vtund_use_sudo,
                                                           tunnel_ip_network=tunnel_ip_network,
                                                           tunnel_near_end_ip=str(self.config_dict['tunnelling_dev_ip_address']),
                                                           tunnel_far_end_ip=str(self.config_dict['rdv_server_ip_address']),
                                                           vtun_server_tcp_port=str(self.vtun_server_port),
                                                           vtun_shared_secret=str(self.config_dict['tunnel_secret']),
                                                           vtun_tunnel_name=str(self.tunnel_name),
                                                           vtun_server_hostname=str(self.vtun_server_hostname),
                                                           mode=self.tunnel_mode,
                                                           vtun_connection_timeout=self.vtun_connection_timeout
                                                           )
            except KeyError:
                raise Exception('IncompleteTunnelParameters')
            
        def check_ping_peer(self):
            """ Check that the tunnel is up and the peer remote inside the tunnel is responding to ping
            \return True if the remote answered within 10 ping attempts, False otherwise
            """
            try:
                attempts = 10
                ping_success = False
                while attempts > 0:
                    cmd = ['ping', '-c' , '1', '-w', '1', str(self.config_dict['rdv_server_ip_address'])] # Send 1 ping and give it 1s to answer
                    rc = subprocess.call(cmd, stdout=open(os.devnull, 'wb'), stderr=subprocess.STDOUT)
                    if rc == 0:
                        ping_success = True
                        break   # Success, exit loop
                    else:
                        attempts -= 1   # One less attemps
                if ping_success == False:
                    raise Exception('PeerNotRespondingToPing')
            except KeyError:
                raise Exception('IncompleteTunnelParameters')

    def _get_vtun_parameters_as_dict(self):
        """ Request the vtun parameters from the RDV server and return them in a dict containing each field as a key together with its value
        \return A dict synthetising the vtun parameters, for example {'tunnel_ip_network': '192.168.101.0', 'tunnel_ip_prefix': '/30', ...}
        """
        vtun_parameters_str = self.run_get_vtun_parameters()
        config_dict = {}
        for line in vtun_parameters_str.splitlines():
            split = line.split(':', 1)  # Cut in key:value
            key = split[0].strip()  # Get rid of leading and trailing whitespaces in key
            value = split[1].strip()  # Get rid of leading and trailing whitespaces in value
            config_dict[key]=value
        return config_dict
    
    def get_client_vtun_tunnel(self, tunnel_mode, vtun_server_hostname, vtun_server_port, vtund_exec = None,  vtund_use_sudo = False, vtun_connection_timeout = 20):
        """ Create a pythonvtunlib.client_vtun_tunnel object based on the configuration returned by the devshell command get_vtun_parameters
        
        If the vtun_parameters_dict provided by the internal call to self._get_vtun_parameters_as_dict() does not have (enough) information to build a client tunnel, an exception will be raised
        \param tunnel_mode The tunnel mode ('L2', 'L3' etc...)
        \param vtun_server_hostname The hostname to connect to (the vtund server)
        \param vtun_server_port The TCP port to use when connecting to the vtund server  
        \param vtund_exec (optional) The PATH to the vtund binary
        \param vtund_use_sudo (optional) A boolean indicating whether the vtund_exec needs to be run via sudo to get root access (False by default)
        \param vtun_connection_timeout How many seconds we give for the tunnel establishment (20 by default)
        \return The resulting ClientVtunTunnelConfig object
        """
        tunnel_name = 'tundev' + str(self._ssh_username)
        config_dict = self._get_vtun_parameters_as_dict()
        try:
            self.ssh_remote_tcp_port = config_dict['rdv_server_vtun_tcp_port']
        except KeyError:
            raise Exception('RDVServerVtunTCPPortIsMandatory')
        
        return TunnellingDev.ClientVtunTunnelConfig(config_dict = config_dict,
                                                    tunnel_mode=tunnel_mode,
                                                    tunnel_name=tunnel_name,
                                                    vtun_server_hostname=vtun_server_hostname,
                                                    vtun_server_port=vtun_server_port,
                                                    vtund_exec = vtund_exec,
                                                    vtund_use_sudo = vtund_use_sudo,
                                                    vtun_connection_timeout = vtun_connection_timeout)
