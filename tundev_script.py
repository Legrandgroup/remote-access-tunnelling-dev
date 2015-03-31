#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import paramiko
import pexpect
import sys

import logging

# def sigwinch_passthrough (sig, data):
#     # Check for buggy platforms (see pexpect.setwinsize()).
#     if 'TIOCGWINSZ' in dir(termios):
#         TIOCGWINSZ = termios.TIOCGWINSZ
#     else:
#         TIOCGWINSZ = 1074295912 # assume
#     s = struct.pack ("HHHH", 0, 0, 0, 0)
#     a = struct.unpack ('HHHH', fcntl.ioctl(sys.stdout.fileno(), TIOCGWINSZ , s))
#     global global_pexpect_instance
#     global_pexpect_instance.setwinsize(a[0],a[1])

class TunnellingDev(object):
    """ Class representing a tunnelling device
    A tunnelling device is a abstract device gathering client devices or server devices
    """
    
    PROTO_RDV_SERVER = '10.10.8.11'
    
    def __init__(self, username, key_filename, logger):
        """
        \param logger A logging.Logger to use for log messages
        """
        self._rdv_server = TunnellingDev.PROTO_RDV_SERVER
        self._ssh_connection = None
        self._ssh_username = username
        self._ssh_key_filename = key_filename
        self._exp = None
        self._prompt = '1001[$] '
        self.logger = logger
    
    def rdv_server_connect(self):
        """ Initiate the ssh connection to the RDV server """
        self._exp = pexpect.spawn('ssh', ['-oUserKnownHostsFile=/dev/null', '-oStrictHostKeyChecking=no', self._ssh_username + '@' + self._rdv_server])
        supposedly_logged_in = False
        surely_logged_in = False
        
        index = self._exp.expect([pexpect.TIMEOUT, 'Permission denied', self._ssh_username + '@.*password: ', self._prompt], timeout=4)
        if self.logger.isEnabledFor(logging.DEBUG):
            self._exp.logfile = sys.stdout    # Log to stdout in DEBUG mode
        
        if index == 0:
            if self._exp.isalive():
                self.logger.info("Supposedly logged in...")
                if self._exp.buffer:
                    self.logger.info("Input buffer is:\n'" + self._exp.buffer + "'")
                self._exp.logfile = None    # Do not log to console anymore , interact will do it
                supposedly_logged_in = True
            else:
                self.logger.error("Remote connection closed")
                exit(5)
        elif index == 1:
            self.logger.error("Permission denied while logging in")
            raise Exception('PermissionDenied')
        elif index == 2:
            self.logger.error("Incorrect password")
            raise Exception('BadPassword')
        elif index == 3:    # linux_prompt_catchall_regexp
            supposedly_logged_in = True    # We are probably logged in
        
        if supposedly_logged_in: print('Supposedly logged in')
    
        if supposedly_logged_in:    # If we think we have been logged in... try to hit return and check if we have a prompt once more
            self._exp.send('\r')    # Wake up terminal (we send a carriage return to find out if we are logged in (in a shell) or not (in the prompt))
            index = self._exp.expect([pexpect.TIMEOUT, pexpect.EOF, self._prompt], timeout=2)
            if index == 0:    # Timeout
                logger.error("Could not wake up terminal")
                exit(5)
            elif index == 1:    # EOF
                logger.error("Remote connection closed")
                exit(5)
            elif index == 2:    # linux_prompt_catchall_regexp a second time
                surely_logged_in = True    # We really think we are logged in now
        if surely_logged_in: print('Surely logged in')
            
#     def rdv_server_connect(self):
#         """ Initiate the ssh connection to the RDV server """
#         self._ssh_connection = paramiko.SSHClient()
#         self._ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # FIXME: really check the server certificate
#         self._ssh_connection.connect(self._rdv_server, username=self._ssh_username, key_filename=self._ssh_key_filename)

    def rdv_server_disconnect(self):
        """ Close the ssh connection to the RDV server if it is up """
        if not self._ssh_connection is None:
            self._ssh_connection.close()

