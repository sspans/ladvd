
[![Build Status](https://travis-ci.org/sspans/ladvd.png)](https://travis-ci.org/sspans/ladvd)

WHAT IS LADVD?
--------------

ladvd is a lldp / cdp / edp / fdp / ndp sender for Unix.

ladvd uses link-layer advertisements to inform switches about connected
hosts, which simplifies Ethernet switch management. It does this by forking
into a privileged parent which handles all raw sockets (and certain ioctls),
and an unprivileged child which creates and parses all packets.
Every 30 seconds the child generates advertisement frames reflecting the
current system state. Interfaces (bridge, bonding, wireless),
capabilities (bridging, forwarding, wireless) and addresses (IPv4, IPv6) 
are detected dynamically. Secondly ladvd can listen for incoming frames
and utilize these for various features (protocol auto-enable, logging,
interface descriptions).


USAGE
-----

Basically you start ladvd like any unix daemon. 
To get a complete list of supported options type

  ladvd -h

and see the manual for more information.


SETUP
-----

Ladvd needs root privileges to initialize the required raw-sockets.
It can run in `daemon' mode, logging to syslog, or in the foreground,
logging to stderr.

To prepare for building ladvd, first run "autoreconf -fi", 
this will create the configure script and makefiles needed to compile ladvd. 
This will only work if autoconf, automake, pkgconfig and libtool are installed.
Feel free to skip this step when building from a release tarball.

To build ladvd, first run the "configure" script. This will create a
Makefile and config.h appropriate for your system. Then type
"make" and optionally "make install". 

Please note that a ladvd user should be created for normal operation.
And that the provided systemd unit-file (for linux systems) uses FHS standard
paths (/usr/sbin) and not the autoconf default (/usr/local/sbin).


BUG REPORTS
-----------

Please create an issue on github or email your bug report to sten@blinkenlights.nl.


COPYRIGHT
---------

ladvd is written by Sten Spans, and may be used, modified and
redistributed only under the terms of the ISC License,
found in the file LICENSE in this distribution.


AVAILABILITY
------------

The main web site for ladvd is http://github.com/sspans/ladvd/
