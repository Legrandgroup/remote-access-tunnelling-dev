#!/bin/sh

if test x`id -u` != x0; then
  echo "This program should be run as root" >&2
  exit 1
fi

echo "Please confirm you want to install all scripts to transform this platform as a onsite by typing 'onsite'"
read var || exit 1
if test x"$var" != x"onsite"; then
  echo "Aborting" >&2
  exit 1
fi

echo "Installing onsite scripts"
set -x
ONSITEDEVSCRIPT_RUNNING=0
if test -e /etc/init.d/onsitedevscript; then
  if /etc/init.d/onsitedevscript status >/dev/null; then
    ONSITEDEVSCRIPT_RUNNING=1
  fi
  /etc/init.d/onsitedevscript stop
fi
cp -f ./onsite-fs/init.d/onsitedevscript /etc/init.d/
if test x"$ONSITEDEVSCRIPT_RUNNING" != x"0"; then
  /etc/init.d/onsitedevscript start
else
  update-rc.d onsitedevscript defaults
fi
