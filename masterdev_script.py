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

class MasterDev(tundev_script.TunnellingDev):
    """ Script to connect to a RDV server from an onsite dev """

    def __init__(self, **kwargs):# See TunnellingDev.__init__ for the inherited kwargs
        """ Constructor
        """
        super(MasterDev, self).__init__(**kwargs)

    def exit(self):
        """ Terminate the onsite dev script """
        self.rdv_server_disconnect()
        if self.logger.isEnabledFor(logging.DEBUG):
            print('')   # Add a carriage return after logout to allow showing the last line before we return to the caller

    def run_show_online_onsite_devs(self):
        """ Run the command show_online_onsite_devs on the remote tundev shell
        \return The output string returned by the RDV server
        """
        return self._strip_trailing_cr_from(self.run_command('show_online_onsite_devs', 4))
    
    def get_online_onsite_dev(self):
        """ Get a list of currently online onsite devices (using the command show_online_onsite_devs on the remote tundev shell)
        \return An array of strings containing onsite dev ID
        """
        try:
            online_onsite_dev_str = self.run_show_online_onsite_devs()
            if online_onsite_dev_str == '':
                return []
            list = online_onsite_dev_str.split('\n')
            return list
        except:
            logger.warning('Failure while parsing result from show_online_onsite_devs')
            return []    # Ignore the exception, return an empty array

    def run_connect_to_onsite_dev(self, id):
        """ Run the command connect_to_onsite_dev on the remote tundev shell, using \p id as the target onsite dev 
        \param id The ID of the remote onsite dev we want to connect to
        """
        self.run_command('connect_to_onsite_dev ' + str(id), 4)
    
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="This program automatically connects to a RDV server as a master device. \
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
    master_dev = MasterDev(username='rpi1101', logger=logger)
    master_dev.rdv_server_connect()
    remote_onsite='rpi1100' # The remote onsite dev to which we want to connect
    unavail_onsite_msg = 'Could not connect to ' + remote_onsite + '. It is not connected (yet). Waiting'
    while True:
        onsite_dev_list = master_dev.get_online_onsite_dev()
        print('Got: "' + str(onsite_dev_list) + '"')
        if remote_onsite in onsite_dev_list:    # We saw our onsite dev available, continue
            break
        else:
            if not unavail_onsite_msg is None:
                logger.warning(unavail_onsite_msg)
                unavail_onsite_msg = None
        
        time.sleep(10)
    
    logger.debug('Selecting onsite dev ' + remote_onsite + ' for this session')
    master_dev.run_connect_to_onsite_dev(remote_onsite) # Now connect to this remote
    
    while True:
        tunnel_mode = master_dev.run_get_tunnel_mode()
        print('Tunnel mode:"' + tunnel_mode + '"')
        master_dev.send_lan_ip_address_for_iface('eth0')
        master_dev.run_set_tunnelling_dev_uplink_type('lan')
        print('Got: "' + master_dev.run_command('echo bla') + '"')
        logger.info('Waiting for vtun tunnel to be allowed by RDV server')
        if master_dev.run_wait_vtun_allowed():
            logger.info('RDV server allowed vtun tunnel')
            break   # This is the only path out, if we get False, we will start again from scratch (as a reply to the 'reset' response)
        else:
            logger.warning('RDV server asked us to restart by sending us a wait_vtun_allowed reply "reset"')
    
    locally_redirected_vtun_server_port = 5000
    vtun_client_config = master_dev.get_client_vtun_tunnel(tunnel_mode,
                                                           vtun_server_hostname='127.0.0.1',
                                                           vtun_server_port=locally_redirected_vtun_server_port,
                                                           vtund_exec='/usr/sbin/vtund',
                                                           vtund_use_sudo=True)  # Returns a pythonvtunlib.client_vtun_tunnel object
    vtun_client = vtun_client_config.to_client_vtun_tunnel_object()
    master_dev._assert_ssh_escape_shell()
    logger.debug('Adding ssh port redirection to ssh session')
    master_dev.ssh_port_forward(locally_redirected_vtun_server_port,
                                master_dev.ssh_remote_tcp_port)
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
    master_dev.exit()
