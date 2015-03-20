#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_PREREQ([2.61])

AC_INIT([ladvd], [1.1.0], [sten@blinkenlights.nl])
AC_CANONICAL_TARGET
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADER([src/config.h])
AM_INIT_AUTOMAKE([subdir-objects foreign])
AM_SILENT_RULES([yes])

# Checks for programs.
AC_PROG_CC
AC_PROG_CC_C99
AM_PROG_CC_C_O
AC_PROG_CXX
AC_PROG_CPP
AC_USE_SYSTEM_EXTENSIONS
AC_PROG_EGREP
AC_PROG_INSTALL
AC_PROG_LIBTOOL
AC_PROG_LN_S
AC_PROG_MAKE_SET
AC_PROG_SED
PKG_PROG_PKG_CONFIG

AC_LANG([C])

case "$target_os" in
    linux-gnu*|linux-uclibc*)
	AC_DEFINE(HAVE_PROC_SYS_NET,1, [define for /proc/sys/net])
	AC_DEFINE(HAVE_SYSFS,1, [define for /sys])
	check_ids=yes
	AC_DEFINE(NETIF_LINUX,1, [define for netifs])
	;;
    freebsd*)
	AC_DEFINE(NETIF_BSD,1, [define for netifs])
	AC_DEFINE([BROKEN_STRNVIS], [1],
	    [FreeBSD strnvis argument order is swapped compared to OpenBSD])
	;;
    openbsd*)
	AC_DEFINE(NETIF_BSD,1, [define for netifs])
	;;
    darwin*)
	AC_DEFINE(NETIF_BSD,1, [define for netifs])
	;;
    solaris*)
	AC_DEFINE(NETIF_BSD,1, [define for netifs])
	;;
    *)
	AC_MSG_ERROR([Unsupported operating system])
	;;
esac

# enable warnings/errors/security
AX_CFLAGS_GCC_OPTION(-Wall -Werror, WCFLAGS)
AX_CFLAGS_GCC_OPTION(-Wformat -Wformat-security, WCFLAGS)
AC_LD_RELRO
AC_CC_PIE
AC_CC_STACK_PROTECTOR
AC_CC_PARAM_SSP_BUFFER_SIZE([4])
AC_CC_D_FORTIFY_SOURCE

AC_SUBST(WARN_CFLAGS,"$WCFLAGS $PIE_CFLAGS")
AC_SUBST(WARN_LDFLAGS,"$RELRO_LDFLAGS $PIE_LDFLAGS")


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
AC_DEFINE(PACKAGE_SOCKET, PACKAGE_PID_DIR "/" PACKAGE_NAME ".sock", [socket])
AC_DEFINE(PACKAGE_CLI, PACKAGE_NAME "c", [cli command])
AC_SUBST([PACKAGE_CLI], "${PACKAGE_NAME}c")

# chroot dir
AC_ARG_WITH([chroot_dir],
	[AS_HELP_STRING([--with-chroot-dir=PATH],[location of the chroot dir])],
	[chroot_dir="$withval"],[])

AS_IF([test -n "$chroot_dir"],
    [AC_DEFINE_UNQUOTED(PACKAGE_CHROOT_DIR,"$chroot_dir",[location of chroot])],
    [AC_DEFINE(PACKAGE_CHROOT_DIR,"/var/run/" PACKAGE_NAME,[location of chroot])]
)

AC_CHECK_FUNC([socket], [], [
 AC_CHECK_LIB([socket], [socket], [LIBS="-lsocket $LIBS"])
])

AC_CHECK_FUNC([gethostent], [], [
 AC_CHECK_LIB([nsl], [gethostent], [LIBS="-lnsl $LIBS"])
])

# check unit tests
PKG_CHECK_MODULES([CHECK], [check >= 0.9.4],
    AC_SUBST([TESTS_SUBDIR], ["tests"])
    AM_CONDITIONAL([TESTS_ENABLED], [true]),
    AM_CONDITIONAL([TESTS_ENABLED], [false]))

# libpci
AS_IF([test -n "$check_ids"],
[
    PKG_CHECK_MODULES(PCI, [libpci >= 3.0.0],
	AC_DEFINE(HAVE_PCI_PCI_H, 1, [have libpci]),
	[
	AC_CHECK_HEADERS([pci/pci.h])
	AC_CHECK_LIB(pci, pci_init, AC_SUBST(PCI_LIBS,"-lpci"))
	])
]
)

# libpcap
AC_ARG_ENABLE([static-libpcap],
    AC_HELP_STRING([--enable-static-libpcap],
		    [build binaries with a static libpcap]),
    [libpcap_static=yes], [libpcap_static=no])

AC_CHECK_HEADER([pcap.h])
AC_CHECK_LIB(pcap, pcap_compile, AC_SUBST(PCAP_LIB,"-lpcap"), 
    AC_MSG_ERROR([libpcap is required]))
AC_CHECK_LIB(pcap, pcap_create,
    AC_DEFINE(HAVE_PCAP_CREATE, 1, [have pcap_create]))
AC_CHECK_LIB(pcap, pcap_set_immediate_mode,
    AC_DEFINE(HAVE_PCAP_IMMEDIATE_MODE, 1, [have pcap_set_immediate_mode]))

AS_IF([test "$libpcap_static" = "no"], 
    [ AC_SUBST(PCAP_LIB,"-lpcap") ],
    [
	# disable -pie, it breaks on the static libpcap
	AC_SUBST(WARN_LDFLAGS,"")
	# more recent linkers support explicit library naming
	# otherwise we try our best to locate the library
	AX_LD_CHECK_FLAG([-l:libpcap.a -lrt], [], [],
	 [AC_SUBST(PCAP_LIB,"-l:libpcap.a -lrt")],
	 [ if test -f "$libdir/libpcap.a"; then
	    AC_SUBST(PCAP_LIB,"$libdir/libpcap.a")
	   elif test -f "/lib/libpcap.a"; then
	    AC_SUBST(PCAP_LIB,"/lib/libpcap.a")
	   elif test -f "/usr/lib/libpcap.a"; then
	    AC_SUBST(PCAP_LIB,"/usr/lib/libpcap.a")
	   elif test -f "/usr/local/lib/libpcap.a"; then
	    AC_SUBST(PCAP_LIB,"/usr/local/lib/libpcap.a")
	   else
	    AC_MSG_ERROR([could not locate libpcap.a])
	   fi
	 ])
    ]
)

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

AC_ARG_ENABLE([static-libevent],
    AC_HELP_STRING([--enable-static-libevent],
		    [build binaries with a static libevent]),
    [libevent_static=yes], [libevent_static=no])

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

      If it is already installed, specify its path using --with-libevent=/dir/
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

AC_CHECK_LIB(event, event_init, [true], AC_MSG_ERROR([libevent is required]))

AS_IF([test "$libevent_static" = "no"], 
    [ AC_SUBST(EVENT_LIB,"-levent") ],
    [
	# disable -pie, it breaks on the static libevent
	AC_SUBST(WARN_LDFLAGS,"")
	# more recent linkers support explicit library naming
	# otherwise we try our best to locate the library
	AX_LD_CHECK_FLAG([-l:libevent.a -lrt], [], [],
	 [AC_SUBST(EVENT_LIB,"-l:libevent.a -lrt")],
	 [ if test $ac_cv_libevent_dir != "(system)"; then
	    AC_SUBST(EVENT_LIB,"$le_libdir/libevent.a -lrt")
	   elif test -f "$libdir/libevent.a"; then
	    AC_SUBST(EVENT_LIB,"$libdir/libevent.a -lrt")
	   elif test -f "/lib/libevent.a"; then
	    AC_SUBST(EVENT_LIB,"/lib/libevent.a -lrt")
	   elif test -f "/usr/lib/libevent.a"; then
	    AC_SUBST(EVENT_LIB,"/usr/lib/libevent.a -lrt")
	   elif test -f "/usr/local/lib/libevent.a"; then
	    AC_SUBST(EVENT_LIB,"/usr/local/lib/libevent.a -lrt")
	   else
	    AC_MSG_ERROR([could not locate libevent.a])
	   fi
	 ])
    ]
)

# evhttp is needed for ladvdc post support
AC_CHECK_HEADERS([event.h], [], AC_MSG_ERROR([libevent headers missing]))
AC_CHECK_HEADERS([evhttp.h], [ AM_CONDITIONAL([HTTP_ENABLED], [true]) ],
	[ AM_CONDITIONAL([HTTP_ENABLED], [false]) ], [ #include <sys/types.h> ])

# systemd check
AC_ARG_WITH([systemdsystemunitdir],
	AS_HELP_STRING([--with-systemdsystemunitdir=DIR], [Directory for systemd service files]),
	[], [with_systemdsystemunitdir=$($PKG_CONFIG --variable=systemdsystemunitdir systemd)])
if test "x$with_systemdsystemunitdir" != xno; then
	AC_SUBST([systemdsystemunitdir], [$with_systemdsystemunitdir])
fi
AM_CONDITIONAL(HAVE_SYSTEMD, [test -n "$with_systemdsystemunitdir" -a "x$with_systemdsystemunitdir" != xno ])

# check for libmnl
PKG_CHECK_MODULES(LIBMNL, [ libmnl ],
    AC_DEFINE(HAVE_LIBMNL, 1, [have libmnl]), :)

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h grp.h pwd.h stdarg.h stdint.h stdio.h syslog.h \
		  sys/file.h sys/utsname.h unistd.h sys/ioctl.h sys/types.h \
		  sys/socket.h sys/time.h sys/uio.h signal.h ctype.h string.h \
		  assert.h time.h ], 
		 [], AC_MSG_ERROR([required header missing]))

# bsd ifmedia
AC_CHECK_HEADERS([asm/types.h linux/sockios.h sys/sockio.h net/if_media.h])
AC_CHECK_HEADERS([net/if.h net/route.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
])
AC_CHECK_HEADERS([net/if_mib.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
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
AC_CHECK_HEADERS([netinet/ether.h])
AC_CHECK_HEADERS([netinet/if_ether.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/in.h>
])
AC_CHECK_HEADERS([net/if_types.h])
AC_CHECK_HEADERS([linux/filter.h], [], [],
[
#include <linux/types.h>
])

# check for libteam
PKG_CHECK_MODULES(LIBTEAM, [ libteam ],
    AC_DEFINE(HAVE_LIBTEAM, 1, [have libteam]), :)

# vlan / bridge / bonding
AC_CHECK_HEADERS([linux/if_vlan.h linux/if_bridge.h \
		  linux/if_bonding.h linux/if_team.h], [], [],
[
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/netdevice.h>
])
# check enums in linux/if_vlan.h
AC_CHECK_DECLS([GET_VLAN_REALDEV_NAME_CMD,GET_VLAN_VID_CMD],[],[],
               [[#include <linux/if_vlan.h>]])

AC_CHECK_HEADERS([net/if_vlan_var.h net/if_bridge.h net/if_bridgevar.h \
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

# kenv and sysctl
AC_CHECK_HEADERS([kenv.h])
AC_CHECK_HEADERS([sys/sysctl.h],[],[],
[
#include <sys/param.h>
])

# linux capabilities
LIBCAP_NG_PATH

AS_IF([test x$CAPNG_LDADD != x], [], [
    AC_CHECK_HEADERS([sys/prctl.h sys/capability.h])
    if test "$ac_cv_header_sys_capability_h" = "yes" ; then
	AC_CHECK_LIB(cap, cap_init, ac_need_libcap=1)
	if test "$ac_cv_lib_cap_cap_init" = "yes"; then
	    AC_DEFINE(HAVE_LIBCAP,1, [define if libcap is available])
	    AC_SUBST(CAP_LDADD,"-lcap")
	fi
    fi
])

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT8_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T

# Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([asprintf memcpy memset snprintf strdup strerror strsep uname \
		socketpair vsyslog],
		[], AC_MSG_ERROR([required function missing]))

AC_CHECK_FUNCS([setresuid setreuid setresgid setregid])

AC_CHECK_FUNCS([setproctitle strlcpy strlcat strnvis __strdup])

AC_CONFIG_FILES([Makefile
                 src/Makefile
                 tests/Makefile
                 doc/Makefile
                 systemd/Makefile])
AC_OUTPUT

