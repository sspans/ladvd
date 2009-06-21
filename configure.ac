#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT([ladvd], [0.8], [sten@blinkenlights.nl])
AC_CANONICAL_TARGET
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([subdir-objects foreign])

# Checks for programs.
AC_PROG_CC
AC_GNU_SOURCE
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AM_PROG_CC_C_O

# enable PIE by default
use_pie=yes

case "$target_os" in
    linux-gnu*)
	AC_DEFINE(HAVE_PROC_SYS_NET,1, [define for /proc/sys/net])
	AC_DEFINE(HAVE_SYSFS,1, [define for /sys])
	AC_DEFINE([TARGET_IS_LINUX], 1, [Define if target OS is Linux])
	;;
    freebsd*)
	case "$target" in
	    x86_64-*-freebsd7.*)
		use_pie=no
	esac
	AC_DEFINE([TARGET_IS_FREEBSD], 1, [Define if target OS is FreeBSD])
	;;
    openbsd*)
	AC_DEFINE([TARGET_IS_OPENBSD], 1, [Define if target OS is OpenBSD])
	;;
    *)
	AC_MSG_ERROR([Unsupported operating system])
	;;
esac

# enable warnings/errors/security
AX_CFLAGS_GCC_OPTION(-Wall -Werror, WCFLAGS)
AX_CFLAGS_GCC_OPTION(-Wformat -Wformat-security, WCFLAGS)
AX_CFLAGS_GCC_OPTION(-D_FORTIFY_SOURCE=2, WCFLAGS)
GCC_STACK_PROTECTOR
AS_IF([test "$use_pie" = "yes"], [
    AX_CFLAGS_GCC_OPTION("-fPIE", WCFLAGS, 
	[ WCFLAGS="$WCFLAGS -fPIE"; WLDFLAGS="-pie"])
])
AC_SUBST(WARN_CFLAGS,"$WCFLAGS")
AC_SUBST(WARN_LDFLAGS,"$WLDFLAGS")

# Enable gcov suport.
AC_ARG_ENABLE([gcov],
AC_HELP_STRING([--enable-gcov],
    [build binaries with gcov support]), [use_gcov=yes], [use_gcov=no])
AS_IF([test "$use_gcov" = yes], [
    CFLAGS="$CFLAGS -fprofile-arcs -ftest-coverage"
    LDFLAGS="$LDFLAGS -fprofile-arcs"
])
AM_CONDITIONAL(GCOV_ENABLED, test "$use_gcov" = yes)

# daemon user
package_user="$PACKAGE_NAME"

AC_ARG_WITH([user],
	    [AS_HELP_STRING([--with-user=USER],[user to switch to])],
	    [package_user="$withval"])
AC_DEFINE_UNQUOTED(PACKAGE_USER,"$package_user",[user to switch to])
AC_SUBST([PACKAGE_USER], ["$package_user"])

# pidfile
AC_ARG_WITH([pid_dir],
	    [AS_HELP_STRING([--with-pid-dir=PATH],[location of the pid file])],
	    [pid_dir="$withval"],[])

AS_IF([test -n "$pid_dir"],
    [AC_DEFINE_UNQUOTED(PACKAGE_PID_DIR,"$pid_dir",[location of pid file])],
    [AC_DEFINE(PACKAGE_PID_DIR,"/var/run",[location of pid file])]
)
AC_DEFINE(PACKAGE_PID_FILE, PACKAGE_PID_DIR "/" PACKAGE_NAME ".pid", [pid file])

# chroot dir
AC_ARG_WITH([chroot_dir],
	[AS_HELP_STRING([--with-chroot-dir=PATH],[location of the chroot dir])],
	[chroot_dir="$withval"],[])

AS_IF([test -n "$chroot_dir"],
    [AC_DEFINE_UNQUOTED(PACKAGE_CHROOT_DIR,"$chroot_dir",[location of chroot])],
    [AC_DEFINE(PACKAGE_CHROOT_DIR,"/var/run/" PACKAGE_NAME,[location of chroot])]
)

# check unit tests
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4], [], [true])

# dlsym
AC_CHECK_LIB(dl, dlsym, AC_SUBST(DL_LIB,"-ldl"))

# libevent
trylibeventdir=""
AC_ARG_WITH(libevent,
       [  --with-libevent=PATH     Specify path to libevent installation ],
       [
                if test "x$withval" != "xno" ; then
                        trylibeventdir=$withval
                fi
       ]
)

dnl ------------------------------------------------------
dnl libevent detection.  swiped from Tor.  modified a bit.

LIBEVENT_URL=http://www.monkey.org/~provos/libevent/

AC_CACHE_CHECK([for libevent directory], ac_cv_libevent_dir, [
  saved_LIBS="$LIBS"
  saved_LDFLAGS="$LDFLAGS"
  saved_CPPFLAGS="$CPPFLAGS"
  le_found=no
  for ledir in $trylibeventdir "" $prefix /usr/local ; do
    LDFLAGS="$saved_LDFLAGS"
    LIBS="$saved_LIBS -levent"

    # Skip the directory if it isn't there.
    if test ! -z "$ledir" -a ! -d "$ledir" ; then
       continue;
    fi
    if test ! -z "$ledir" ; then
      if test -d "$ledir/lib" ; then
        LDFLAGS="-L$ledir/lib $LDFLAGS"
      else
        LDFLAGS="-L$ledir $LDFLAGS"
      fi
      if test -d "$ledir/include" ; then
        CPPFLAGS="-I$ledir/include $CPPFLAGS"
      else
        CPPFLAGS="-I$ledir $CPPFLAGS"
      fi
    fi
    # Can I compile and link it?
    AC_TRY_LINK([#include <sys/time.h>
#include <sys/types.h>
#include <event.h>], [ event_init(); ],
       [ libevent_linked=yes ], [ libevent_linked=no ])
    if test $libevent_linked = yes; then
       if test ! -z "$ledir" ; then
         ac_cv_libevent_dir=$ledir
       else
         ac_cv_libevent_dir="(system)"
       fi
       le_found=yes
       break
    fi
  done
  LIBS="$saved_LIBS"
  LDFLAGS="$saved_LDFLAGS"
  CPPFLAGS="$saved_CPPFLAGS"
  if test $le_found = no ; then
    AC_MSG_ERROR([libevent is required.  You can get it from $LIBEVENT_URL

      If it's already installed, specify its path using --with-libevent=/dir/
])
  fi
])

if test $ac_cv_libevent_dir != "(system)"; then
  if test -d "$ac_cv_libevent_dir/lib" ; then
    LDFLAGS="-L$ac_cv_libevent_dir/lib $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir/lib"
  else
    LDFLAGS="-L$ac_cv_libevent_dir $LDFLAGS"
    le_libdir="$ac_cv_libevent_dir"
  fi
  if test -d "$ac_cv_libevent_dir/include" ; then
    CPPFLAGS="-I$ac_cv_libevent_dir/include $CPPFLAGS"
  else
    CPPFLAGS="-I$ac_cv_libevent_dir $CPPFLAGS"
  fi
fi

AC_CHECK_LIB(event, event_init, AC_SUBST(EVENT_LIB,"-levent"),
				AC_MSG_ERROR([libevent is required]))

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h grp.h pwd.h stdarg.h stdint.h stdio.h syslog.h \
		  sys/file.h sys/utsname.h unistd.h sys/ioctl.h sys/types.h \
		  sys/socket.h sys/time.h signal.h ctype.h string.h event.h \
		  assert.h time.h ], 
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
AC_CHECK_HEADERS([net/ethertypes.h])
AC_CHECK_HEADERS([netinet/in.h])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
])
AC_CHECK_HEADERS([net/if_types.h])
AC_CHECK_HEADERS([linux/filter.h])

# bridge / bonding
AC_CHECK_HEADERS([linux/if_bridge.h linux/if_bonding.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
])
AC_CHECK_HEADERS([net/if_bridge.h net/if_bridgevar.h \
		  net/if_lagg.h net/if_trunk.h net/if_bond_var.h], [], [],
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
	AC_SUBST(CAP_LIB,"-lcap")
	use_capabilities=yes
    fi
fi

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([asprintf memcpy memset snprintf strdup strerror uname \
		socketpair vsyslog],
		[], AC_MSG_ERROR([required function missing]))

AC_CHECK_FUNCS([setproctitle strlcpy strlcat])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile
                 doc/Makefile])
AC_OUTPUT

