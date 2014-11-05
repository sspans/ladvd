#!/bin/bash

# Exit on first error
set -xe

save_and_shutdown() {
  # save built for host result
  # force clean shutdown
  halt -f
}

# make sure we shut down cleanly
trap save_and_shutdown EXIT SIGINT SIGTERM

# go back to where we were invoked
cd $WORKDIR

# configure path to include /usr/local
export PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin

# can't do much without proc!
mount -t proc none /proc

# pseudo-terminal devices
mkdir -p /dev/pts
mount -t devpts none /dev/pts

# shared memory a good idea
mkdir -p /dev/shm
mount -t tmpfs none /dev/shm

# sysfs a good idea
mount -t sysfs none /sys

# pidfiles and such like
mkdir -p /var/run
mount -t tmpfs none /var/run
mount -t tmpfs none /tmp

# enable ip forwarding
echo 1 > /proc/sys/net/ipv4/ip_forward
echo 1 > /proc/sys/net/ipv4/conf/all/forwarding

# create interfaces
ip link add dev veth0 type veth peer name veth1
ip link set veth0 up
ip link set veth1 up
ip link add dev bond0 type bond || :
ip link add dev veth11 type veth peer name veth13
ip link add dev veth12 type veth peer name veth14
ip link set dev veth11 master bond0
ip link set dev veth12 master bond0
ip link set bond0 up
ip link add link bond0 name bond0.42 type vlan id 42
ip link set bond0.42 up
ip link add dev br0 type bridge
ip link set br0 up
ip link add dev veth21 type veth peer name veth23
ip link set veth21 up
ip link add dev veth22 type veth peer name veth24
ip link set veth22 up
ip link set dev veth21 master br0
ip link set dev veth22 master br0
ip tuntap add dev eth1 mode tap
ip link set eth1 up

# configure networking
ip addr add 127.0.0.1 dev lo
ip -6 addr add ::1/128 dev lo
ip link set lo up
ip addr add 203.0.113.1/24 dev veth0
ip -6 addr add 2001:DB8::dead:cafe:babe/64 dev veth0
ip link set veth0 up

# configure dns (google public)
mkdir -p /run/resolvconf
echo 'nameserver 8.8.8.8' > /run/resolvconf/resolv.conf
mount --bind /run/resolvconf/resolv.conf /etc/resolv.conf

# setup ladvd
chmod 755 /var/run
mkdir /var/run/ladvd

# setup ladvdc
[ -e src/ladvdc ] || ln src/ladvd src/ladvdc

# XXX: hack to capture gcov from chroot
mkdir /var/run/ladvd/home
mount -o bind /home /var/run/ladvd/home

# print usage
./src/ladvd -h || :
# run ladvd once
./src/ladvd -a -d -f -o -LCEFN -w -c NL -z -m veth0 -e veth13 -e veth14 -vv >/dev/null
# run tests
make check

