#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import tundev_script

class OnsiteDev(tundev_script.TunnellingDev):
    """ Script to connect to a RDV server from an onsite dev """

    def __init__(self):
        super(OnsiteDev, self).__init__()

    def run_cmd(self, command):
        """ Execute this command on the remote server """
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
        """ Terminate the onsite dev script """
        self.rdv_server_disconnect()

if __name__ == '__main__':
    print('Starting onsite dev script');
    onsite_dev = OnsiteDev()
    onsite_dev.rdv_server_connect()
    onsite_dev.run_cmd('echo bla')
    onsite_dev.exit()
