# Setting up tunnels manually

This section explains how to manually setup the ssh connection inside a TLS tunnel (using stunnel), manually.
These steps are actually automated by the remote access framework, but can also be executed manually on a terminal.

## Server side stunnel

The fist part takes place on the server side (we use a Raspberry Pi here, but it could also be the RDV server).

As a first step, generate an SSL certificate (after having setup the default values of certificates from the file `tools/stunnel.cnf` provided with stunnel's sources):
```
openssl req -new -x509 -days 3650 -nodes -config /home/pi/stunnel-5.10/tools/stunnel.cnf -out /home/pi/stunnel-5.10/compiled/etc/stunnel/stunnel.pem -keyout /home/pi/stunnel-5.10/compiled/etc/stunnel/stunnel.pem
```

In this example, the self-signed generated TLS certificate will be saved into the file `/home/pi/stunnel-5.10/compiled/etc/stunnel/stunnel.pem`

Create a stunnel daemon config file containing:
```
pid = /var/run/stunnel.pid
debug = 7
output = /var/log/stunnel.log
foreground = yes
cert = /home/pi/stunnel-5.10/compiled/etc/stunnel/stunnel.pem
key = /home/pi/stunnel-5.10/compiled/etc/stunnel/stunnel.pem
[ssh-in-fake-https]
accept  = 443
connect = 22
```

Run the stunnel service:
```
/home/pi/stunnel-5.10/compiled/bin/stunnel /home/pi/stunnel-5.10/compiled/etc/stunnel/stunnel.conf
```

## Client side stunnel

This takes place on a second device (we use a Raspberry Pi here as well, it acts as a tunnelling dev, from which the connection is initiated).

Create a stunnel daemon config file containing the following lines (Saved it as `~/stunnel_rpi_test.conf):
```
pid = /tmp/stunnel_test.pid
debug = 7
output = /tmp/stunnel_test.log
foreground = yes
client = yes
[ssh-in-fake-https]
accept = 127.0.0.1:2222
connect = 10.10.8.41:443
```

Note: 10.10.8.41 is the stunnel server IP address (RDV server or other).


Run the stunnel client:

```
stunnel4 ~/stunnel_rpi_test.conf
```

Logs will appear on the server side, a connection should be established.

Once the stunnel connection is up and running, the client can start an ssh connection to the stunnel server.
From a terminal on the client, while keeping the stunnel session established, start an ssh connection:
```
ssh -oPort=2222 user@localhost
```

Where `user` should be replaced by a valid user account on the stunnel server machine.

Note that the sshd service must be running and listening to TCP port 22 for this to work.

## ssh port fowarding

Once stunnel and ssh are both running, from the ssh connection, enter an escaped CLI inside ssh.
Add a new port redirection from client TCP port 30324 to server TCP port 30324.

## Server side vtun

On the vtun server side (Raspberry Pi acting as a tunnelling device), create a vtun configuration file with the following content:
```
options {
  port 30324;            # Listen on this port.
  # Syslog facility
  syslog        daemon;
  # Path to various programs
  ifconfig      /sbin/ifconfig;
}
legrand {
  passwd      abcd;
  type        tun;
  proto       tcp;
  compress    zlib:3;
  encrypt     no;
  stat        yes;
  keepalive   yes;
  up {
    ip "link set %% up multicast off mtu 1446";
    ip "-family inet addr add 192.168.47.2 peer 192.168.47.1 dev %%";
  };
  down {
    ifconfig "%% down";
  };
}
``` 

And launch the vtun server:
```
/home/pi/vtun-3.0.3/compiled/sbin/vtund -s -f /etc/vtund.conf
```

## Client side vtun

Once this is done, reate a vtun config file containing:
```
options {
    port           30324;
    syslog         daemon;
    ifconfig       /sbin/ifconfig;
    ip             /sbin/ip;
}
legrand {
    passwd abcd;
    stat           yes;
    keepalive      yes;
    persist        yes;
    timeout        30;
    up {
    ip "link set %% up multicast off mtu 1446";
    ip "-family inet addr add 192.168.47.1 peer 192.168.47.2 dev %%";
    };
    down {
        ifconfig "%% down";
    };
}
``` 

We will then launch vtun via the following command:

```
vtund -f vtunc.conf legrand localhost
```

This will trigger the vtun tunnel creation, you should see logs on both server and client vtun processes (check the logs).

Also, the client and server should be able to communicate together.

From the client, you should be able to ping the remote server: ```ping 192.168.47.2``` and vice versa.
