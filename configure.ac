#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(ladvd, 0.6.0, sten@blinkenlights.nl)
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE
AC_PROG_INSTALL

if test -n "$GCC"; then
    CFLAGS="$CFLAGS -Wall"
fi

AC_ARG_ENABLE(debug,
[  --enable-debug           Enable debugging options (bugreports and developers only)],
	enable_debug="$enableval", enable_debug="no")

if test "x$enable_debug" = "xyes"; then
    CFLAGS="$CFLAGS -DDEBUG"
fi

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h grp.h pwd.h stdarg.h stdint.h stdio.h syslog.h \
		  sys/file.h sys/utsname.h unistd.h sys/ioctl.h sys/types.h \
		  sys/socket.h sys/time.h signal.h], 
		 [], AC_MSG_ERROR([required header missing]))

# bsd ifmedia
AC_CHECK_HEADERS([asm/types.h linux/sockios.h net/if_media.h])
AC_CHECK_HEADERS([net/if.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
])

# ethtool
AC_CHECK_HEADERS([linux/ethtool.h], [], [],
[
#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif
])

# ethernet
AC_CHECK_HEADERS([net/ethernet.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
])
AC_CHECK_HEADERS([net/if_types.h])

# bridge / bonding
AC_CHECK_HEADERS([linux/if_bridge.h linux/if_bonding.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
])
AC_CHECK_HEADERS([net/if_bridge.h net/if_bridgevar.h \
		  net/if_lagg.h net/if_trunk.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
#ifdef HAVE_NET_ETHERNET_H
#include <net/ethernet.h>
#endif /* HAVE_NET_ETHERNET_H */
#ifdef HAVE_NETINET_IF_ETHER_H
#include <netinet/if_ether.h>
#endif /* HAVE_NETINET_IF_ETHER_H */
])

# wireless
AC_CHECK_HEADERS([linux/wireless.h], [],[],
[
#ifdef HAVE_ASM_TYPES_H
#include <asm/types.h>
#endif
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
])
AC_CHECK_HEADERS([net80211/ieee80211.h])
AC_CHECK_HEADERS([net80211/ieee80211_ioctl.h], [],[],
[
#include <sys/param.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>

#include <net80211/ieee80211.h>
])

# raw
AC_CHECK_HEADERS([netpacket/packet.h])
AC_CHECK_HEADERS([net/bpf.h])
AC_CHECK_HEADERS([net/if_dl.h])

#sysctl
AC_CHECK_HEADERS([sys/sysctl.h], [], AC_MSG_ERROR([required header missing]),
[
#include <sys/param.h>
])

# linux capabilities
AC_CHECK_HEADERS([sys/prctl.h sys/capability.h])
if test "$ac_cv_header_sys_capability_h" = "yes" ; then
    AC_CHECK_LIB(cap, cap_init, ac_need_libcap=1)
    if test "$ac_cv_lib_cap_cap_init" = "yes"; then
	AC_DEFINE(USE_CAPABILITIES,1,
	[define if capabilities should be used])
	AC_SUBST(CAP_LIBS,"-lcap")
	use_capabilities=yes
    fi
fi

# daemon user
AC_ARG_WITH([user],
	    [AS_HELP_STRING([--with-user=USER],[user to switch to])],
	    [user="$withval"],[])

AS_IF([test -n "$user"],
    [AC_DEFINE_UNQUOTED(PACKAGE_USER,"$user",[user to switch to])],
    [AC_DEFINE(PACKAGE_USER,PACKAGE_NAME,[user to switch to])]
)

# pidfile
AC_ARG_WITH([pid_dir],
	    [AS_HELP_STRING([--with-pid-dir=PATH],[location of the pid file])],
	    [pid_dir="$withval"],[])

AS_IF([test -n "$pid_dir"],
    [AC_DEFINE_UNQUOTED(PACKAGE_PID_DIR,"$pid_dir",[location of pid file])],
    [AC_DEFINE(PACKAGE_PID_DIR,"/var/run",[location of pid file])]
)
AC_DEFINE(PACKAGE_PID_FILE, PACKAGE_PID_DIR "/" PACKAGE_NAME ".pid", [pid file])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([asprintf memcpy memset snprintf strdup strerror uname vsyslog], [], AC_MSG_ERROR([required function missing]))

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
