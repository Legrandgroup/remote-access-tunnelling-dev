#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import os
import sys

import tundev_script
import argparse
import logging

import time

import threading
import signal

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
        
    def run_set_tunnel_mode(self, tunnel_mode):
        """ Run the command set_tunnel_mode on the remote tundev shell
        \param tunnel_mode The tunnel mode as a string (usual values 'L2' or 'L3')
        """
        #raise Exception('NotImplementedYet')
        self.run_command('set_tunnel_mode ' + str(tunnel_mode), 2)
    
if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="This program automatically connects to a RDV server as a master device. \
and automates the typing of tundev shell commands from the tunnelling devices side in order to setup a tunnel session", prog=progname)
    parser.add_argument('-d', '--debug', action='store_true', help='display debug info', default=False)
    parser.add_argument('-T', '--with-stunnel', dest='with_stunnel', action='store_true', help='connect to RDVServer throught local stunnel instead of directly through SSH', default=False)
    parser.add_argument('-m', '--tunnel-mode', dest='tunnel_mode', help='the OSI level for the tunnel (L2 or L3)', default='L3')
    parser.add_argument('-t', '--session-time', type=int, dest='session_time', help='specify session duration (in seconds)', default=-1)
    parser.add_argument('-o', '--onsite', type=str, action='store', help='ID of the onsite device to connect to', default=None)
    args = parser.parse_args()

    # Setup logging
    logging.basicConfig()
    
    if args.onsite is None:
        print(progname + ': Error: --onsite argument is mandatory', file=sys.stderr)
        exit(1)
    else:
        remote_onsite=args.onsite # The remote onsite dev to which we want to connect
    
    logger = logging.getLogger(progname)
    
    if args.debug:
        logger.setLevel(logging.DEBUG)
    else:
        logger.setLevel(logging.INFO)
    
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(levelname)s %(asctime)s %(name)s:%(lineno)d %(message)s"))
    logger.addHandler(handler)
    logger.propagate = False
    
    logger.debug('Starting as PID ' + str(os.getpid()))
    
    username = 'rpi1101'
    master_dev = MasterDev(username=username, logger=logger)
    
    msg = 'Connecting to RDV server'
    if args.with_stunnel:
        msg += ' over an SSL tunnel'
    else:
        msg += ' directly over SSH (' + str(master_dev.get_rdv_server()) + ')'
    msg += ' as user account "' + username + '"'
    logger.info(msg)
    master_dev.rdv_server_connect(using_stunnel=args.with_stunnel)
    logger.info('Connecting to onsite ' + remote_onsite)
    unavail_onsite_msg = 'Could not connect to ' + remote_onsite + '. It is not connected (yet). Waiting'
    while True:
        onsite_dev_list = master_dev.get_online_onsite_dev()
        if remote_onsite in onsite_dev_list:    # We saw our onsite dev available, continue
            break
        else:
            if not unavail_onsite_msg is None:
                logger.warning(unavail_onsite_msg)
                unavail_onsite_msg = None
        
        time.sleep(10)
    
    master_dev.send_lan_ip_address_for_iface('eth0')
    master_dev.run_set_tunnel_mode(args.tunnel_mode)
    #master_dev.run_set_tunnelling_dev_uplink_type('lan')
    logger.info('Selecting onsite dev ' + remote_onsite + ' for this session')
    master_dev.run_connect_to_onsite_dev(remote_onsite) # Now connect to this remote
    
    # Sanity check
    if master_dev.run_get_role() != 'master':
        logger.error('Tundev shell returns a role that does not match this script (master)')
        raise Exception('RoleMismatch')
    
    tunnel_mode = master_dev.run_get_tunnel_mode()
    
    locally_redirected_vtun_server_port = 5000
    vtun_client_config = master_dev.get_client_vtun_tunnel(tunnel_mode,
                                                           vtun_server_hostname='127.0.0.1',
                                                           vtun_server_port=locally_redirected_vtun_server_port,
                                                           vtund_exec='/usr/local/sbin/vtund',
                                                           vtund_use_sudo=True)  # Returns a pythonvtunlib.client_vtun_tunnel object
    
    vtun_client = vtun_client_config.to_client_vtun_tunnel_object()
    master_dev._assert_ssh_escape_shell()
    logger.debug('Adding ssh port redirection to ssh session')
    master_dev.ssh_port_forward(locally_redirected_vtun_server_port,
                                master_dev.ssh_remote_tcp_port)
     
    vtun_client.start()
    logger.debug('Started local vtun client as PID ' + str(vtun_client._vtun_pid))
    if tunnel_mode == 'L3':
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
    if args.session_time >= 0:
        print('Now sleeping ' + str(args.session_time/60) + ' min ' + str(args.session_time%60) + ' s')
        time.sleep(args.session_time)
    else:
        print('Waiting until issue on vtund client or ssh session')
        
        #We prepare and event to be set when either ssh or vtun client falls down
        event_down = threading.Event()
        event_down.clear()
        
        #We prepare 3 events to be set in order to have a better idea of what failed
        event_ssh_down = threading.Event()
        event_ssh_down.clear()
        event_vtun_down = threading.Event()
        event_vtun_down.clear()
        event_signal_received = threading.Event()
        event_signal_received.clear()
        
        #To set the event if we catch SIGINT, SIGTERM or SIGQUIT
        def signalHandler(signum, frame):
            logger.info('Handled signal ' + str(signum))
            event_signal_received.set()
            event_down.set()
        
        #Thread to run to wait a process to end and then set the event
        class processWaiter(threading.Thread):
            def __init__(self, process_to_wait, event_to_set_for_logging):
                super(processWaiter,self).__init__()
                self.setDaemon(True)
                self._process = process_to_wait
                self.log_event = event_to_set_for_logging
            def run(self):
                self._process.wait()
                self.log_event.set()
                event_down.set()
        
        #Create 2 of those thread : one for ssh and one for vtun client
        ssh_waiter = processWaiter(master_dev.get_ssh_process(), event_ssh_down)
        vtun_client_waiter = processWaiter(vtun_client.get_vtun_process(), event_vtun_down) #FIXME: Change python vtunlib in order to remove the direct access to 'private' attribute
        
        #Launch those threads
        ssh_waiter.start()
        vtun_client_waiter.start()
        
        #We connect signal to handler
        signal.signal(signal.SIGINT, signalHandler)
        signal.signal(signal.SIGTERM, signalHandler)
        signal.signal(signal.SIGQUIT, signalHandler)
        #We wait for the event in block mode and therefore the session will last 'forever' if neither ssh nor vtun client falls down 
        while not event_down.is_set():
            event_down.wait(1) #Wait without timeout can't be interrupted by unix signal so we wait the signal with a 1 second timeout and we do that until the even is set.
        #We disconnect signal from handler
        signal.signal(signal.SIGINT, signal.SIG_DFL)
        signal.signal(signal.SIGTERM, signal.SIG_DFL)
        signal.signal(signal.SIGQUIT, signal.SIG_DFL)
        
        if event_signal_received.is_set():
            logger.info('Stopped by receiving signal')
        if event_ssh_down.is_set():
            logger.error('Stopped by losing SSH Connection')
        if event_vtun_down.is_set():
            logger.error('Stopped by losing Vtun Tunnel')
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
