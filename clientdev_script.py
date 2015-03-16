#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import tundev_script

class ClientDev(tundev_script.TunnellingDev):
    """ Script to connect to a RDV server from a client dev """

    def __init__(self):
        tundev_script.TunnellingDev.__init__(self)

    def run_cmd(self, command):
        """run
        Execute this command on the remote server"""
        if command:
            if self._ssh_connection:
                print('Host: %s'  % (self._rdv_server))
                stdin, stdout, stderr = self._ssh_connection.exec_command(command)
                stdin.close()
                print('Dumping output...\n')
                for line in stdout.read().splitlines():
                    print('host: %s: %s' % (self._rdv_server, line))
                print('...Done\n')

    def exit(self):
        """ Terminate the client dev script """
        self.rdv_server_disconnect()

if __name__ == '__main__':
    print('Starting client');
    client = ClientDev()
    client.rdv_server_connect()
    client.run_cmd('echo bla')
    client.exit()
