#!/bin/sh

if test x`id -u` != x0; then
  echo "This program should be run as root" >&2
  exit 1
fi

echo "Please confirm you want to install all scripts to transform this platform as a master by typing Y"
read var || exit 1
if test x"$var" != x"Y"; then
  echo "Aborting" >&2
  exit 1
fi

echo "Installing master scripts"
set -x
cp -f ./master-fs/usr/local/sbin/master-secondary-if-watcher.py /usr/local/sbin/
cp -f ./master-fs/etc/dbus-1/system.d/secondary-if-watcher /etc/dbus-1/system.d/
IFWATCHER_RUNNING=0
if test -e /etc/init.d/ifwatcher; then
  if /etc/init.d/ifwatcher status >/dev/null; then
    IFWATCHER_RUNNING=1
  fi
  /etc/init.d/ifwatcher stop
fi
cp -f ./master-fs/etc/init.d/ifwatcher /etc/init.d
if test x"$IFWATCHER_RUNNING" != x"0"; then
  /etc/init.d/ifwatcher start
fi
