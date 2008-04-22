#                                               -*- Autoconf -*-
# Process this file with autoconf to produce a configure script.

AC_INIT(ladvd, 0.4.2, sten@blinkenlights.nl)
AM_INIT_AUTOMAKE([-Wall -Werror foreign])
AC_CONFIG_SRCDIR([src/config.h.in])
AC_CONFIG_HEADER([src/config.h])

# Checks for programs.
AC_PROG_CC

# Checks for libraries.
AC_CHECK_LIB([net], [libnet_init])
AC_CACHE_SAVE

# Checks for header files.
AC_HEADER_STDC
AC_CHECK_HEADERS([fcntl.h malloc.h sys/file.h syslog.h unistd.h libnet.h])

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
