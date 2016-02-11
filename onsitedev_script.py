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
pid_file_path = '/tmp/onsitedevscriptinstance.pid'

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

    def run_wait_master_connection(self):
        """ Run the command wait_master_connection on the remote tundev shell
        
        Will block as long as we do not get a reply "ready or "reset"
        \return True if we get a "ready" reply, meaning we can run the command get_vtun_parameters
        \return False if we get a "reset" reply, meaning we need to start over from scratch again, and check again the tunnel mode
        """
        while True:
            response = self._strip_trailing_cr_from(self.run_command('wait_master_connection', 90))   # 90 here must be higher than the maximum blocking time of wait_master_connection (see specs)
            if response == 'ready':
                return True
            elif response == 'reset':
                return False
            elif response == 'not_ready':
                continue    # Loop again (this is the only path that would loop forever
            else:
                self.logger.error('Unknown reply from tundev shell command wait_master_connection: ' + response)
                raise Exception('TundevShellSyntaxError')

if __name__ == '__main__':
    # Parse arguments
    parser = argparse.ArgumentParser(description="This program automatically connects to a RDV server as an onsite device. \
and automates the typing of tundev shell commands from the tunnelling devices side in order to setup a tunnel session", prog=progname)
    parser.add_argument('-d', '--debug', action='store_true', help='display debug info', default=False)
    parser.add_argument('-T', '--with-stunnel', dest='with_stunnel', action='store_true', help='connect to RDVServer throught local stunnel instead of directly through SSH', default=False)
    parser.add_argument('-t', '--session-time', type=int, dest='session_time', help='specify session duration (in seconds)', default=-1)
    parser.add_argument('-u', '--3g-uplink-dev', type=str, dest='uplink_dev_3g', help='use a pre-established 3G link on device dev', default=None)
    parser.add_argument('-p', '--write-pid-file', dest='write_pid_file', action='store_true', help='write pid in file for daemonisation purpose', default=False)

    args = parser.parse_args()

    # Setup logging
    logging.basicConfig()
    
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
    
    #Writing pid to pid_file_path
    if args.write_pid_file:
        pid_file = open(str(pid_file_path), 'w')
        pid_file.write(str(os.getpid()))
        pid_file.close()
        
    username = 'rpi1100'
    onsite_dev = OnsiteDev(username=username, logger=logger)
    
    if not args.uplink_dev_3g is None:  # We must add the specific route to the rdv server before we execute rdv_server_connect()
        onsite_dev.add_host_route(host_ip=onsite_dev.get_rdv_server(), iface=args.uplink_dev_3g, ip_use_sudo=True)
    
    msg = 'Connecting to RDV server'
    if args.with_stunnel:
        msg += ' over an SSL tunnel'
    else:
        msg += ' directly over SSH (' + str(onsite_dev.get_rdv_server()) + ')'
    msg += ' as user account "' + username + '"'
    logger.info(msg)
    onsite_dev.rdv_server_connect(using_stunnel=args.with_stunnel)
    # Sanity check
    if onsite_dev.run_get_role() != 'onsite':
        logger.error('Tundev shell returns a role that does not match this script (onsite)')
        raise Exception('RoleMismatch')

    while True:
        tunnel_mode = onsite_dev.run_get_tunnel_mode()
        onsite_dev.send_lan_ip_address_for_iface('eth0')
        if args.uplink_dev_3g is None:
            onsite_dev.run_set_tunnelling_dev_uplink_type('lan')
        else:
            onsite_dev.run_set_tunnelling_dev_uplink_type('3g')
        
        logger.info('Waiting for a master to request us to start our vtun tunnel to the RDV server')
        if onsite_dev.run_wait_master_connection():
            logger.info('RDV server allowed vtun tunnel')
            break   # This is the only path out, if we get False, we will start again from scratch (as a reply to the 'reset' response)
        else:
            logger.warning('RDV server asked us to restart by sending us a wait_master_connection reply containing "reset"')
    
    #Updating tunnel mode according to masterdev tunnel mode
    tunnel_mode = onsite_dev.run_get_tunnel_mode()
    
    locally_redirected_vtun_server_port = 5000
    vtun_client_config = onsite_dev.get_client_vtun_tunnel(tunnel_mode,
                                                           extremity_if='eth0',
                                                           vtun_server_hostname='127.0.0.1',
                                                           vtun_server_port=locally_redirected_vtun_server_port,
                                                           vtund_exec='/usr/local/sbin/vtund',
                                                           vtund_use_sudo=True,
                                                           nat_to_external=(tunnel_mode == 'L3')   # Always use a NAT towards the LAN for onsite devices in L2 mode
                                                          )  # Returns a pythonvtunlib.client_vtun_tunnel object
    
    vtun_client = vtun_client_config.to_client_vtun_tunnel_object()
    onsite_dev._assert_ssh_escape_shell()
    logger.debug('Adding ssh port redirection to ssh session')
    onsite_dev.ssh_port_forward(locally_redirected_vtun_server_port,
                                onsite_dev.ssh_remote_tcp_port)
        
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
        logger.info('Tunnel to RDV server is up (got a ping reply)')
    if args.session_time >= 0:
        print('Now sleeping ' + str(args.session_time/60) + ' min ' + str(args.session_time%60) + ' s')
        time.sleep(args.session_time)
    else:
        print('vtund over ssh session now established')
        
        #We prepare an event to be set when either ssh or vtun client falls down
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
        ssh_waiter = processWaiter(onsite_dev.get_ssh_process(), event_ssh_down)
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
            #onsite_dev.run_command('echo .')
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
    onsite_dev.exit()