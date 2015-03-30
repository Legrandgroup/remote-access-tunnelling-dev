#!/usr/bin/python

# -*- coding: utf-8 -*-

from __future__ import print_function

import paramiko

class TunnellingDev(object):
    """ Class representing a tunnelling device
    A tunnelling device is a abstract device gathering client devices or server devices
    """
    
    PROTO_RDV_SERVER = '10.10.8.11'
    
    def __init__(self):
        self._rdv_server = TunnellingDev.PROTO_RDV_SERVER
        self._ssh_connection = None

    def rdv_server_connect(self):
        """ Initiate the ssh connection to the RDV server """
        self._ssh_connection = paramiko.SSHClient()
        self._ssh_connection.set_missing_host_key_policy(paramiko.AutoAddPolicy())  # FIXME: really check the server certificate
        self._ssh_connection.connect(self._rdv_server, username='rpi0001', password='cl0001')

    def rdv_server_disconnect(self):
        """ Close the ssh connection to the RDV server if it is up """
        if not self._ssh_connection is None:
            self._ssh_connection.close()

