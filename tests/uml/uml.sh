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

# enable ipv4 forwarding for docker
echo 1 > /proc/sys/net/ipv4/ip_forward

# configure networking
ip addr add 127.0.0.1 dev lo
ip link set lo up
ip addr add 10.1.1.1/24 dev eth0
ip link set eth0 up
ip route add default via 10.1.1.254

# create interfaces
ip link add dev veth0 type veth peer name veth1
ip link set veth0 up
ip link add dev bond0 type bond || :
ip link set bond0 up
ip link add dev veth11 type veth peer name veth13
ip link set veth11
ip link add dev veth12 type veth peer name veth14
ip link set veth12
ip link set dev veth11 master bond0
ip link set dev veth12 master bond0
ip link add link bond0 name bond0.42 type vlan id 42
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

# configure dns (google public)
mkdir -p /run/resolvconf
echo 'nameserver 8.8.8.8' > /run/resolvconf/resolv.conf
mount --bind /run/resolvconf/resolv.conf /etc/resolv.conf

# run tests
make check

