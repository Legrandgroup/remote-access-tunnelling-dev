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

    def __init__(self, username, logger, key_filename = None):
        """ Constructor
        \param username The username to use with ssh to connect to the RDV server
        \param key_filename A file containing the private key for key-based ssh authentication
        \param logger A logging.Logger to use for log messages
        """
        super(OnsiteDev, self).__init__(username=username, key_filename=key_filename, logger=logger)

    def exit(self):
        """ Terminate the onsite dev script """
        self.rdv_server_disconnect()
        if self.logger.isEnabledFor(logging.DEBUG):
            print('')   # Add a carriage return after logout to allow showing the last line before we return to the caller

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
    onsite_dev = OnsiteDev(username = 'rpi1001', logger = logger)
    onsite_dev.rdv_server_connect()
    tunnel_mode = onsite_dev.run_get_tunnel_mode()
    print('Tunnel mode:"' + tunnel_mode + '"')
    onsite_dev.send_lan_ip_address_for_iface('eth0')
    onsite_dev.run_set_tunnelling_dev_uplink_type('lan')
    print('Got :"' + onsite_dev.run_command('echo bla') + '"')
    vtun_client = onsite_dev.get_client_vtun_tunnel(tunnel_mode, vtund_exec = '/usr/sbin/vtund')  # Returns a pythonvtunlib.client_vtun_tunnel object
    vtun_client.start()
    onsite_dev.exit()
