#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import sys

import tundev_script
import argparse
import logging

import time

progname = os.path.basename(sys.argv[0])

class OnsiteDev(tundev_script.TunnellingDev):
    """ Script to connect to a RDV server from an onsite dev """

    def __init__(self, **kwargs):# See TunnellingDev.__init__ for the inherited kwargs
        """ Constructor
        """
        super(OnsiteDev, self).__init__(**kwargs)

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
    onsite_dev = OnsiteDev(username='rpi1100', logger=logger)
    onsite_dev.rdv_server_connect()
    while True:
        tunnel_mode = onsite_dev.run_get_tunnel_mode()
        print('Tunnel mode:"' + tunnel_mode + '"')
        onsite_dev.send_lan_ip_address_for_iface('eth0')
        onsite_dev.run_set_tunnelling_dev_uplink_type('lan')
        print('Got: "' + onsite_dev.run_command('echo bla') + '"')
        logger.info('Waiting for vtun tunnel to be allowed by RDV server')
        if onsite_dev.run_wait_vtun_allowed():
            logger.info('RDV server allowed vtun tunnel')
            break   # This is the only path out, if we get False, we will start again from scratch (as a reply to the 'reset' response)
        else:
            logger.warning('RDV server asked us to restart by sending us a wait_vtun_allowed reply "reset"')
    
    locally_redirected_vtun_server_port = 5000
    vtun_client_config = onsite_dev.get_client_vtun_tunnel(tunnel_mode,
                                                           vtun_server_hostname='127.0.0.1',
                                                           vtun_server_port=locally_redirected_vtun_server_port,
                                                           vtund_exec='/usr/sbin/vtund',
                                                           vtund_use_sudo=True)  # Returns a pythonvtunlib.client_vtun_tunnel object
    vtun_client = vtun_client_config.to_client_vtun_tunnel_object()
    onsite_dev._assert_ssh_escape_shell()
    logger.debug('Adding ssh port redirection to ssh session')
    onsite_dev.ssh_port_forward(locally_redirected_vtun_server_port,
                                onsite_dev.ssh_remote_tcp_port)
    vtun_client.start()
    logger.debug('Started local vtun client as PID ' + str(vtun_client._vtun_pid))
    try:
        vtun_client_config.check_ping_peer()
    except:
        logger.error('Peer does not respond to pings inside the tunnel')
        session_output = vtun_client.get_output()
        session_output = '|' + session_output.replace('\n', '\n|')  # Prefix the whole output with a | character so that dump is easily spotted
        if session_output.endswith('|'):    # Remove the last line that only contains a | character
            session_output = session_output[:-1]
        while session_output.endswith('|\n'):   # Get rid of the last empty line(s) that is/are present most of the time
            session_output = session_output[:-2]
        print('Tunnel was not properly setup (no ping response from peer). Output from vtund client was:\n' + session_output, file=sys.stderr)
        raise Exception('TunnelNotWorking')
    logger.debug('Tunnel to RDV server is up (got a ping reply)')
    print('Now sleeping 15s')
    time.sleep(15)
    print('...done')
    vtun_client.stop()
    session_output = vtun_client.get_output()
    session_output = '|' + session_output.replace('\n', '\n|')  # Prefix the whole output with a | character so that dump is easily spotted
    if session_output.endswith('|'):    # Remove the last line that only contains a | character
        session_output = session_output[:-1]
    while session_output.endswith('|\n'):   # Get rid of the last empty line(s) that is/are present most of the time
        session_output = session_output[:-2]
    print('Now exitting tundev script. For debug, output from vtund client was:\n' + session_output , file=sys.stderr)
    onsite_dev.exit()
