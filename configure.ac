#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(ladvd, 0.4.2, sten@blinkenlights.nl)
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC
AC_ARG_VAR(HAVE_LIBNET_CONFIG)
AC_CHECK_PROG(HAVE_LIBNET_CONFIG, libnet-config, yes)
if test "$HAVE_LIBNET_CONFIG" = yes; then
CPPFLAGS="$CPPFLAGS `libnet-config --defines`"
else
AC_MSG_ERROR([could not find the (required) libnet-config program])
fi

# Checks for libraries.
AC_CHECK_LIB([net], [main], [], [AC_MSG_ERROR(could not find the (required) libnet library)])
AC_CACHE_SAVE

AC_CHECK_LIB(net, libnet_init_packet,
[AC_DEFINE(LIBNET_API_VERSION, 100, [The API version of libnet.])
AC_MSG_NOTICE([libnet version: < 1.1.0])],
[AC_CHECK_LIB(net, libnet_init,
[AC_DEFINE(LIBNET_API_VERSION, 110, [The API version of libnet.])
AC_MSG_NOTICE([libnet version: >= 1.1.0])],
[AC_MSG_ERROR([could not identify the version of libnet])])])

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h malloc.h sys/file.h syslog.h unistd.h], [], AC_MSG_ERROR([required header missing]))
AC_CHECK_HEADERS([libnet.h], [], AC_MSG_ERROR([libnet headers missing]))

# Checks for typedefs, structures, and compiler characteristics.
AC_C_CONST
AC_TYPE_SIZE_T
AC_TYPE_UINT16_T
AC_TYPE_UINT32_T
AC_TYPE_UINT8_T

# Checks for library functions.
AC_FUNC_VPRINTF
AC_CHECK_FUNCS([bzero strdup strerror uname])

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
