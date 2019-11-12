# Introduction 

This documentation details a step-by-step procedure to setup a new onsite or master tunnelling device.

We initially start from a Raspberry PI device running Raspbian OS. We need a 4GB SD card, even though 8GB is a more reasonable minimum storage capacity.

# Installation of required packages
```
sudo apt-get install liblzo2-dev libssl-dev bison flex lsof tcpdump openssh-client python-ipaddr python-pexpect python-gobject bridge-utils stunnel4 python-dbus
```

# Overview of required software

This section gives information about how to assemble the various software modules that are required for the Raspberry device to issue a tunnel to the RDV server.

When using the `-T` option (see below), we will carry the tunnel from onsite/master device to RDV server inside an TLS tunnel.
This SSL tunnel will traverse firewalls the same was as an HTTPs connection.

We thus need to enable the tunnelling device RPI to initiate an TLS connction on TCP port 443.

For this, we will use the existing tool *stunnel*.

*stunnel* provides us with an end-to-end TCP connection between two processes: one on the tunnelling dev, the orher one on the RDV server.
This is done seamlessly for these two processes, that only see a local TCP connection. *stunnel* will handle the TLS session for thes processes.

Once this TLS session is established, we actually setup an *ssh* connection on to of *stunnel*. *ssh* will take care of public-key authentication as well as multiplexing sessions inside the same authenticated *ssh* session.

The secondary multiplexed connection within *ssh* will carry another layer-2 or layer-3 tunnel implemented by the utility *vtun* in IP-mode (tun) or Ethernet-mode (tap) respectively.

# Installing software recompiled from source

## Considerations about vtun

Using vtun-3.0.4 seems to lead to issues during execution of up/down commands of vtun's configuration script.

The symptom of this issue is an error message displayed about fork() being unusable.

This does not occur with vtun version 3.0.3, we will thus use that version on tunnelling devices.

## Using your distribution's vtun package

Before compiling from sources, you can first check that the default shipped vtun package for Raspbian can be used.
You should make sure this is version 3.0.3, if it is another version, you can either give it a try (keeping in mind the warning above) of recompile from source (see below).


```
sudo apt-get install vtund
```
or on recent Raspbian distributions:

```
sudo apt-get install vtun
```

## Compiling vtun from sources

This section explains the recompilation of vtun from its source files.
You can safely skip this if vtun has been installed directly from the official package as detailed above.

In order to recompile vtun, [download its source files from the official website](http://sourceforge.net/projects/vtun/)

We will use vtun-3.0.3

After decompressing the archive, compile vtun directly on the RPI:

```
./configure --enable-ssl --enable-zlib --enable-lzo --prefix=`pwd`/compiled/
make
sudo make install
```

Warning: The `sudo make install` may fail with an error message mentionning "strip command not found". If this is the case, this can be easily fixed by editing the Makefile file in the source directoy, and modify the `install:` target, remplacing `$(BIN_DIR)/strip` by only `strip`.
We remove the absolute path from the strip command, which will allow the *make* process to use the OS-provided strip command (while the `configure` step seems to mistakenly prefix it with the installation prefix instead)

Once *vtund* is compiled locally on the tunnelling device, we have to make this new executable utility available to scripts. In order to seamlessly make it available in the path, we will create a symbolic link in a more *standard* directory:
```
sudo ln -s `pwd`/compiled/sbin/vtund /usr/sbin/vtund
```
Note: This step can only be performed if there is no already installed distribution wide vtund utility, otherwise the link creation may fail.

## Installation of common software for tunnelling device

### Fetching the remote access scripts

# Software installation

This software relies on [a library to drive vtun from python code](https://github.com/Legrandgroup/pythonvtunlib), that we will checkout inside a subfolder `pythonvtunlib` inside the sources.

In the home directory of the Rapsberry (ususally `/home/pi`), get a copy of the remote access software.
For example, using git, type:
```
cd
git clone https://github.com/Legrandgroup/remote-access-tunnelling-dev.git
cd remote-access-tunnelling-dev/
git clone https://github.com/Legrandgroup/pythonvtunlib.git
```

As you have probably noted, there are two nested repositories to clone.

### Asymmetic ssh key generation

Generate a public/private ssh key pair on the tunnelling device (as user pi):
```
ssh-keygen
```

Copy the public key from the newly generated file in to the RDV server's allowed keys (`~/.ssh/authorized_hosts`) for the UNIX account associated with the tunnelling device. For this, please follow the related procedure on the RDV server instructions.
(in those instructions, the content of the environment variable `KEY` that will be set on the RDV server has to be copied over  from the content of file `~/.ssh/id_rsa.pub` on the tunnelling device.

### Generating an account on the RDV server

For each tunnelling device (onsite or master) that is allowed to connect to the RDV server, a configuration first needs to be done on the RDV server itself.
See the [related documentation for more information](https://github.com/Legrandgroup/remote-access-rdv-server/blob/master/INSTALL.md#account-creation).

During this process a new username (UNIX account) will be created.

In the examples below, we will assume that username *rpi1111* was created for the master RPI and *rpi1108* for the onsite RPI.

### Ajusting the IP address of the RDV server

In the file `tundev_script.py`, you can modify the variable `PROTO_RDV_SERVER` and set it to the public IP address of the RDV server (it is the same IP address that will be configured in the stunnel config file below)

### Customizing the script to use the account created on the RDV server

An RDV server account must now have been reserved and configured on the RDV server before continuing on these instructions. If this is not the case, please follow the related procedure on the RDV server instructions.
The tunnelling device must now be configured to use the UNIX account, so that the scripts will authenticate using that account username.
In order to do this, add a line in file `~/.profile` (as user pi), that will set the appropriate environment variable:

For a master RPI, for example, if the username created on the RDV server is *rpi1111*:
```
export MASTERDEV_USERNAME=rpi1111
```

For an onsite RPI, , for example, if the username created on the RDV server is *rpi1108*:
```
export ONSITEDEV_USERNAME=rpi1108
```

Also, add a line that will provide the IP address or hostname of the RDV server:
```
export RDV_SERVER_HOSTNAME=my.rdv.server.com
```

Once these environment variables configured, close the current shell and reopen it. You should see this variable set in the new shell, check this by running:
```
printenv | grep _USERNAME=
```

### Testing connectivity using ssh

This step allows us to make sure that the public key of the RPI has been properly associated with a valid account on the RDV server.

In the following example, we are testing that an onsite RPI can connect to the RDV server.
`RDV_SERVER_HOSTNAME` has been set in `~/.profile` above and is now available as an environment variable to the shell.
`ONSITEDEV_USERNAME` or `MASTERDEV_USERNAME` is also available as an environment variable.

From a terminal on the onsite RPI, as user pi, run:
```
ssh $ONSITEDEV_USERNAME@$RDV_SERVER_HOSTNAME
```
For an onsite RPI using username *rpi1108* and a configured RDV server *my.rdv.server.com*, this is equivalent to:
```
ssh rpi1108@my.rdv.server.com
```

Or for a master RPI, as user pi, run:
```
ssh $MASTERDEV_USERNAME@$RDV_SERVER_HOSTNAME
```

If this connection works properly, you can directly run the automated tunnelling device script (first in directly over ssh, without stunnel, which may not work if your firewall drops outgoing ssh connections on port 22):

For a master RPI:
```
cd ~/remote-access-tunnelling-dev/
./masterdev_script.py -d -l
```

For an onsite RPI:
```
cd ~/remote-access-tunnelling-dev/
./onsitedev_script.py -d
```

Note: obviously, your RPI will need to have a working connection to the Internet, and in particular to the RDV server.

For all command examples below, when using relative directories, we will now assume that we are running our commands from the current working directory `~/remote-access-tunnelling-dev/` (as we did for the previous examples above).

### Making sure the ping command works!

A few distributions (Raspbian Jessie amongst other) only allow root to run ping.
You can check this by running ping from a terminal, and if it fails, by running sudo ping instead.

If ping only works as root (via sudo), you can manually edit to code to change the argument `ping_use_sudo` provided when invoking method `tundev_script.TunnellingDev.get_client_vtun_tunnel()`.
To do this, depending on the tunnelling device role (onsite or master), edit onsitedev_script.py or masterdev_script.py (and check the invokation of its method `OnsiteDev.get_client_vtun_tunnel()` or `MasterDev.get_client_vtun_tunnel()`, that is to say, add argument ping_use_sudo=True in the code at the loction:
```
vtun_client_config = onsite_dev.get_client_vtun_tunnel(...)
```

### Configuring stunnel for encapsulating the SSH connection into a TLS session

In order to configure stunnel (required for this encapsulation, create a file named `/etc/stunnel/outgoing_rdv_remote.conf` that will contain:
```
[rdv_remote]
client = yes
accept = 222
connect = <RDV_server_IP_address>:443
```
Where <RDV_server_IP_address> should be replaced by the public IP address of the RDV server

Once configured, restart stunnel:
```
sudo /etc/init.d/stunnel4 stop;sudo /etc/init.d/stunnel4 start
```

As a double-check, you can make sure that a process called stunnel uis running and listens on TCP port 222 (on some distributions, and especially those using systemd, the start command returns OK, but stunnel may however not be started):
```
ps -ef|grep stunnel
netstat -an|grep 222
```
If the service is not running, and on recent distros (based on systemctl), the following command should allow to diagnose the issue:
```
sudo systemctl status stunnel4.service
```
Getting `active (exited)` will tell you stunnel was actually not stared. You should see `active (running)` here.
Often, this might come from the needed activation of the stunnel service beforehand (please consult your distro manual, this often ends up into editing `/etc/defaults/stunnel` or `/etc/defaults/stunnel4` and add the following line:
```
ENABLED=1
```

## Finishing the configuration for an onsite RPI

### Manually testing the connection from an onsite dev

In order to first test that an onsite dev properly connects to the RDV server, we will run the following command from a terminal on the RPI, as user pi:
```
./onsitedev_script.py -d
```
Or if ssh connections are filtered by a firewall on the way, add the `-T` option:
```
./onsitedev_script.py -d -T
```
If an exception occurs, please check that the account (rpi11xx) has properly been created on the RDV server.

Note that this relies on ONSITEDEV_USERNAME variable to be set properly, otherwise, you can also provide the account username on the command line using the `-u` argument when running script onsitedev_script.py above.

If module iptable_nat is not automatically loaded on the onsite dev, it will need to be loaded at boot time (this module is required for NAT function to work, and this will be needed as soon as a master to onsite session is setup in layer-3 mode (default))

## onsitedev_script running automatically at boot time

While the section above was about running the onsite dev script manually, we will now automate this so that the onsite RPI will automatically connect to the RDV server, in an unattended way.

The script `onsitedev_script.sh` (provided in the remote-access-tunnelling-dev repository) allows to run an infinite try-over loop, that will continuously launch the python script `onsitedev_script.py`

In `onsitedev_script.sh`, `onsitedev_script.py` is launched with argument `-p` so that its PID is dumped inside a temporary file. This option is used to allow stopping the onsitedev service.

By setting the variable ONSITEDEV_USERNAME in the environment above, this information will automatically be propagated to onsitedev_script, thus the pre-configured username will be used.

By copying the file `onsite-fs/init.d/onsitedevscript` into `/etc/init.d/` on the onsite RPI, the connection to the RDV server will automatically be started at boot time (as a UNIX daemon).
```
sudo cp ./onsite-fs/init.d/onsitedevscript /etc/init.d/
```

You will also have to double-check that the path set in variable `DAEMON`, inside the code of that init script, correctly points to where your `onsidedev_script.sh` is located.

As a first test, check that this init script starts and stop the service properly, using the following commands:
```
sudo /etc/init.d/onsitedevscript start
sudo /etc/init.d/onsitedevscript stop
```

Once this init script has proven to work properly, it can be automatically launched at boot time by running the following command:
```
sudo update-rc.d onsitedevscript defaults
```

Restarting the Raspberry PI will prove that the onsite script automatically launches after a reboot without any user interaction.
It could thus be shipped to the target network.

## Using a 3G uplink

First of all, the 3G adapter (most often USB dongle) should be supported on the onsite RPI.

The 3G USB dongle Huawei E220 has been tested successfully on our setup. The instructions below thus apply to that model but should be easily adapted to any simular hardware.

When the 3G USB dongle is inserted, lsusb will return a line like:
```
Bus 001 Device 008: ID 12d1:1003 Huawei Technologies Co., Ltd. E220 HSDPA Modem / E230/E270/E870 HSDPA/HSUPA Modem
```

### usb-modeswitch

Some USB dongles also act as a mass storage to provide a virtual disk space containing their drivers. If this is the case, the utility usb-modeswitch can be used to force the dongle to be recognised as a modem (rather than mass-storage device):
```
sudo apt-get install usb-modeswitch
```
For more information, please see [here](http://bigcowpi.blogspot.fr/2013/03/raspberry-pi-as-3g-huawei-e303-wireless.html)
You will also have to make sure usb_modeswitch will take care of your USB device, by editing `/etc/usb_modeswitch.conf` with the following configuration:
```
# Configuration for the usb_modeswitch package, a mode switching tool for
# USB devices providing multiple states or modes
#
# This file is evaluated by the wrapper script "usb_modeswitch_dispatcher"
# in /usr/sbin
# To enable an option, set it to "1", "yes" or "true" (case doesn't matter)
# Everything else counts as "disable"
# Disable automatic mode switching globally (e.g. to access the original
# install storage)
#DisableSwitching=0
# Enable logging (results in a extensive report file in /var/log, named
# "usb_modeswitch_<interface-name>"
EnableLogging=0
# choose one of these:
#DetachStorageOnly=1
DefaultVendor=0x12d1
DefaultProduct=0x1003
#TargetClass=0xff
CheckSuccess=20
HuaweiMode=1
```

Once the configuration is done, run usb_modeswitch on the RPI:
```
sudo usb_modeswitch -c /etc/usb_modeswitch.conf
```

### Additional packages required or 3G uplink

The following packages will be needed on the RPI:
```
sudo apt-get install ppp
```

Also, you will need to make sure that the package `vwdial`is *not* installed on the Raspberry PI (if it were, sakis3g would use it to launch the pppd connection, which is not what we want):
```
sudo apt-get remove vwdial
```

### 3G connection script

Fetch a sample 3G connection script (sakis3g):
```
wget "http://downloads.sourceforge.net/project/vim-n4n0/sakis3g.tar.gz?r=http%3A%2F%2Fsourceforge.net%2Fprojects%2Fvim-n4n0%2Ffiles%2F&ts=1363537696&use_mirror=tene~t" -O /tmp/sakis3g.tar.gz
sudo mkdir /opt/sakis3g
cd /opt/sakis3g
sudo tar -xvzf /tmp/sakis3g.tar.gz
sudo chmod a+x sakis3g
```
If a PIN code is required on the SIM card, it should be provided iniside the configuration file `/etc/sakis3g.conf`:
```
SIM_PIN="0000"
```

You can now test the 3G connection, the first time, this can be done manually in order to set the proper value to all parameters (sakis3g's interactive mode):
```
sudo /opt/sakis3g/sakis3g --interactive
```

Be careful to correctly set the connection type to `USBMODEM`, and to properly input the USB vendor and product ID of the USB dongle (Huawei 3G 220 for our example), as well as the mobile APN (that should match you 3G data subscription).

Once the notification page mentionning "Connected to..." is displayed, we will have the confirmation that all parameters are correct.

At this stage, select `More option` -> `Generate success report`

A report printed on the scree will then contain all configuration variables for the 3G connection setup.

In the line prefixed with `Variables:`, write down the values associated to:
```
OTHER
USBMODEM
APN
```
Add variables `NOSMART` and `PPPD_OPTIONS` as follows, then connect to 3G using the full command line, that will look like (this example is for our example, adapt it to your dongle):
```
sudo OTHER=USBMODEM USBMODEM=12d1:1003 APN='ebouygtel.com' APN_USER='none' APN_PASS='none' NOSMART=y PPPD_OPTIONS='modem crtscts -detach nodefaultroute dump noipdefault usehostname ktune logfd 2 noauth name sakis3g lock maxfail 3' /opt/sakis3g/sakis3g --console connect
```

The value for `USBMODEM` should match the USB identifiers for the 3G dongle (printed out when running lsusb)

The value for `APN` really depends on your mobile operator (you should thus check your subscription to find out which APN to use)

Setting argument variable `DEBUG=y` when running sakis3g will provide verbose information concerning the connection stage.

Using argument `NOSMART=y` asks saki3g not to force the RPI's default gateway to use the 3G connection (we will thus continue to use the LAN interface as our default route).
Routing and DNS lookup will thus not be modified by the 3G link going up.
The only missing step to use the 3G link will be to setup a specific route (via the 3G connection) to the machine we have to contact via the 3G link (for us, this will be the public IP address of the RDV server).

The value of `PPPD_OPTIONS` is an override of the default for sakis3g. The default behaviour being `usepeerdns` that we have removed, and `defaultroute` that we have remplaced by `nodefaultroute`.

A list of configuration related to french operators' APN is available [here](http://www.sosandroid.fr/forumAndroid/topic421.html)

You can now manually request a disconnection from the 3G network (for our setup):
```
sudo OTHER=USBMODEM USBMODEM=12d1:1003 APN='ebouygtel.com' /opt/sakis3g/sakis3g --console disconnect
```

If the manual connection and disconnection works, the configuration variables can be saved into sakis3g's configuration file `/etc/sakis3g.conf`:
```
OTHER=USBMODEM
USBMODEM=12d1:1003
APN=ebouygtel.com
APN_USER=none
APN_PASS=none
```

Warning: please not that variables above are *not* protected by single or double quotes.
Also, `NOSMART` and `PPPD_OPTIONS` are missing from this configuration, and will be forced by the init script below.

Run once more sakis3g without argument to check your `/etc/sakis3g.conf` config is correct:
```
sudo /opt/sakis3g/sakis3g connect
sudo /opt/sakis3g/sakis3g disconnect
``` 

Once satisfied by the connection/disconnection process, create a script saved inside `/etc/init.d/sakis3g` that will contain the following code:
```
#! /bin/sh
# /etc/init.d/sakis3g

### BEGIN INIT INFO
# Provides:          sakis3g
# Required-Start:    $remote_fs $syslog
# Required-Stop:     $remote_fs $syslog
# Default-Start:     
# Default-Stop:      0 1 2 3 4 5 6
# Short-Description: Sets the 3G connection up and down
# Description:       Starts and stop a 3G connection via the sakis3g utility
### END INIT INFO

DAEMON=/opt/sakis3g/sakis3g
NAME=sakis3g
DESC="3G uplink"
# This is for sakis3g to avoid messing around with this host routes and dns entries
export NOSMART=y
export PPPD_OPTIONS='modem crtscts -detach nodefaultroute dump noipdefault usehostname ktune logfd 2 noauth name sakis3g lock maxfail 3'

case "$1" in
  start)
    echo -n "Starting $DESC: "
    if /opt/sakis3g/sakis3g connect; then
      echo "$NAME."
    else
      echo "Failed"
      exit 2
    fi
    ;;
  stop)
    echo -n "Stopping $DESC: "
    if /opt/sakis3g/sakis3g disconnect; then
      echo "$NAME."
    else
      echo "Failed"
      exit 2
    fi
    ;;
  *)
    echo "Usage: /etc/init.d/sakis3g {start|stop}"
    exit 1
    ;;
esac

exit 0
```

We decided not to run update.rc.d or create symbolic links in /etc/rc?.d for this init script, because we want it to be manually launched (and not start a 3G connection at boot time).

## Finishing the configuration for a master RPI

### Manually testing the connection from an master dev

In order to first test that a master dev properly connects to the RDV server, we will run the following command from a terminal on the RPI, as user pi:
```
./masterdev_script.py -d
```
Or if ssh connections are filtered by a firewall on the way, add the `-T` option:
```
./masterdev_script.py -d -T
```
If an exception occurs, please check that the account (rpi11xx) has properly been created on the RDV server.

Note that this relies on MASTERDEV_USERNAME variable to be set properly, otherwise, you can also provide the account username on the command line using the `-u` argument when running script masterdev_script.py above.

## Automatical secondary interface configuration

It is highly recommended to add a 2nd Ethernet interface to the master RPI master. This can be done by connecting a USB to Ethernet adapter on one of the free USB ports on the RPI.

This network interface will then need to be configured with IP parameters. This will be done automatically using the provided script `master-fs/usr/local/sbin/master-secondary-if-watcher.py`.
This script watches for network interfaces status change (link up/down) and reacts accordingly by starting the necessary services.

Installer this script into directory `/usr/local/sbin` and create the following D-Bus configuration into /etc/dbus-1:
```
sudo apt-get install dnsmasq
sudo cp ./master-fs/usr/local/sbin/master-secondary-if-watcher.py /usr/local/sbin/
sudo cp ./master-fs/etc/dbus-1/system.d/secondary-if-watcher /etc/dbus-1/system.d/
```

This will suppress any required IP configuration on the machine on the Ethernet cable connected to the USB to Ethernet dongle.
If that machine has DHCP enabled, it will automatcially be configured and will get a default route to the onsite network automatically.

This `usr/local/sbin/master-secondary-if-watcher.py` must be started automatically as a boot time daemon, so as to permanently make sure the Ethernet interface (handled by the Ethernet to USB dongle) is properly configured and a DHCP server is running on it.

A version of the init script to perform this task is provided as `master-fs/init.d/ifwatcher` in this repository.
First, you should make sure that the path of the variable DAEMON inside that script is valid and corresponds to the location of script `master-secondary-if-watcher.py`
Then, you can try to manually start and stop this service and make sure the script starts and stops by checking the list of processes:
```
sudo ./master-fs/etc/init.d/ifwatcher start;ps -ef|grep master-secondary-if-watcher.py
sudo ./master-fs/etc/init.d/ifwatcher stop;ps -ef|grep master-secondary-if-watcher.py
```

Finally, if everything works as expected, the init script should be copied over to `/etc/init.d/` and enabled on the master Raspberry PI:
```
sudo cp ./master-fs/etc/init.d/ifwatcher /etc/init.d/
sudo update-rc.d ifwatcher defaults
```

Warning: New versions of D-Bus require a different D-Bus policy file in /etc/dbus-1/system.d:
```
<!DOCTYPE busconfig PUBLIC
 "-//freedesktop//DTD D-BUS Bus Configuration 1.0//EN"
 "http://www.freedesktop.org/standards/dbus/1.0/busconfig.dtd">
<busconfig>
  <policy user="root">
    <allow own="com.legrandelectric.RemoteAccess.SecondaryIfWatcher"/>
    <allow send_destination="com.legrandelectric.RemoteAccess.SecondaryIfWatcher"/>
    <allow receive_sender="com.legrandelectric.RemoteAccess.SecondaryIfWatcher"/>
  </policy>
  <policy context="default">
    <allow own="com.legrandelectric.RemoteAccess.SecondaryIfWatcher"/>
    <allow send_destination="com.legrandelectric.RemoteAccess.SecondaryIfWatcher"/>
    <allow receive_sender="com.legrandelectric.RemoteAccess.SecondaryIfWatcher"/>
  </policy>
</busconfig>
```

Restarting the master RPI will validate the fact that this daemon is properly started at boot time.
When connecting a machine via an Ethernet cable to the USB to Ethernet adapter, that machine should get an IP address.
If you check the DHCP server IP address, it will corresponds to the master RPI IP address, to which you can connect using ssh.
