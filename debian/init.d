#!/bin/sh

### BEGIN INIT INFO
# Provides:        ladvd
# Required-Start:  $network $remote_fs $syslog
# Required-Stop:   $network $remote_fs $syslog
# Default-Start:   2 3 4 5
# Default-Stop:    0 1 6
# Short-Description: Start ladvd
### END INIT INFO

PATH=/usr/local/sbin:/usr/local/bin:/sbin:/bin:/usr/sbin:/usr/bin

. /lib/lsb/init-functions

NAME=ladvd
DAEMON=/usr/sbin/$NAME
PIDFILE=/var/run/$NAME.pid

test -x $DAEMON || exit 5

# Include defaults if available
if [ -f /etc/default/$NAME ] ; then
	. /etc/default/$NAME
fi

set -e

case "$1" in
  start)
	# create the privsep empty dir if necessary
	if [ ! -d /var/run/ladvd ]; then
	    mkdir /var/run/ladvd
	    chmod 0755 /var/run/ladvd
	fi

	log_begin_msg "Starting $NAME: "
	start-stop-daemon --start --quiet --oknodo --pidfile $PIDFILE \
		--exec $DAEMON -- $DAEMON_OPTS
        log_end_msg $?
	;;
  stop)
	log_begin_msg "Stopping $NAME: "
	start-stop-daemon --stop --quiet --oknodo --pidfile $PIDFILE \
		--exec $DAEMON
	log_end_msg $?
	;;
  restart|force-reload)
	$0 stop && sleep 2 && $0 start
	;;
  *)
	echo "Usage: $0 {start|stop|restart|force-reload}"
	exit 1
	;;
esac

exit 0
