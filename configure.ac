#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(ladvd, 0.4.2, sten@blinkenlights.nl)
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC

if test -n "$GCC"; then
    CFLAGS="$CFLAGS -Wall"
fi

AC_ARG_ENABLE(debug,
[  --enable-debug           Enable debugging options (bugreports and developers only)],
	enable_debug="$enableval", enable_debug="no")

if test "x$enable_debug" = "xyes"; then
    CFLAGS="$CFLAGS -DDEBUG"
fi

AC_ARG_WITH(libnet_includes,
	[  --with-libnet-includes=DIR     libnet include directory],
	[with_libnet_includes="$withval"],[with_libnet_includes="no"])

AC_ARG_WITH(libnet_libraries,
	[  --with-libnet-libraries=DIR    libnet library directory],
	[with_libnet_libraries="$withval"],[with_libnet_libraries="no"])

if test "x$with_libnet_includes" != "xno"; then
    CPPFLAGS="${CPPFLAGS} -I${with_libnet_includes}"
fi  

if test "x$with_libnet_libraries" != "xno"; then
    LDFLAGS="${LDFLAGS} -L${with_libnet_libraries}"
fi

# Checks for libraries.
AC_CHECK_LIB(net, main, [], [AC_MSG_ERROR([cannot find libnet])])
AC_CHECK_LIB(net, libnet_init_packet,
    [
	AC_MSG_ERROR([libnet version: < 1.1.0])
    ], [
	AC_CHECK_LIB(net, libnet_init,
	    [
	    AC_DEFINE(LIBNET_API_VERSION, 110, [libnet API version])
	    AC_MSG_NOTICE([libnet version: >= 1.1.0])
	    ], [
	    AC_MSG_ERROR([could not identify the version of libnet])
	    ])
])

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
AC_CHECK_FUNCS([asprintf])
AC_CHECK_FUNCS([bzero strdup strerror uname vsyslog], [], AC_MSG_ERROR([required function missing]))

AC_CONFIG_FILES([Makefile
                 src/Makefile])
AC_OUTPUT
