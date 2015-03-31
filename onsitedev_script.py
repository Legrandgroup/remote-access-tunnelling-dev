#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import sys

import tundev_script
import argparse
import logging

progname = os.path.basename(sys.argv[0])

class OnsiteDev(tundev_script.TunnellingDev):
    """ Script to connect to a RDV server from an onsite dev """

    def __init__(self, username, key_filename, logger):
        super(OnsiteDev, self).__init__(username=username, key_filename=key_filename, logger=logger)

    def run_cmd(self, command):
        """ Execute this command on the remote server """
        if command:
            if self._ssh_connection:
                print('Host: %s'  % (self._rdv_server))
                #stdin, stdout, stderr = self._ssh_connection.exec_command(command)
                #stdin.close()
                #print('Dumping output...\n')
                #for line in stdout.read().splitlines():
                #    print('host: %s: %s' % (self._rdv_server, line))
                #print('...Done\n')
                channel = self._ssh_connection.invoke_shell()
                channel.send('echo bla\r')
                result = ''
                while channel.recv_ready():
                    result += channel.recv(1024)
                print('Got output:' + result)

    def exit(self):
        """ Terminate the onsite dev script """
        self.rdv_server_disconnect()

if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="This program automatically connects to a RDV server. \
and automates the typing of tundev shell commands from the tunnelling devices side in order to setup a tunnel session", prog=progname)
    parser.add_argument('-d', '--debug', action='store_true', help='display debug info', default=False)
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig()
    
    logger = logging.getLogger(__name__)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(asctime)s %(name)s():%(lineno)d %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    
    logger.debug(progname + ": Starting")
    print('Starting onsite dev script');
    onsite_dev = OnsiteDev(username = 'rpi1001', key_filename = '/home/lionel/.ssh/id_rsa', logger = logger)
    onsite_dev.rdv_server_connect()
    onsite_dev.run_cmd('echo bla')
    onsite_dev.exit()
