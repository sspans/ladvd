#! /bin/sh

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
DAEMON=/usr/sbin/ladvd
PIDFILE=/var/run/$NAME.pid

test -x $DAEMON || exit 5

# Include ladvd defaults if available
if [ -f /etc/default/ladvd ] ; then
	. /etc/default/ladvd
fi

set -e

case "$1" in
  start)
	log_begin_msg "Starting $NAME: "
	start-stop-daemon --start --quiet --pidfile $PIDFILE \
		--exec $DAEMON -- $DAEMON_OPTS
        log_end_msg $?
	;;
  stop)
	log_begin_msg "Stopping $NAME: "
	start-stop-daemon --stop --quiet --pidfile $PIDFILE \
		--exec $DAEMON
	log_end_msg $?
	;;
  restart)
	$0 stop && sleep 2 && $0 start
	;;
  *)
	echo "Usage: $0 {start|stop|restart}"
	exit 1
	;;
esac

exit 0
