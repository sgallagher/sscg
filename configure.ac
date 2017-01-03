AC_PREREQ(2.59)
m4_include([version.m4])

AC_INIT([sscg],
        VERSION_NUMBER,
        [sgallagh@redhat.com])

AC_CONFIG_SRCDIR([COPYING])
AC_CONFIG_AUX_DIR([build])

m4_ifdef([AC_USE_SYSTEM_EXTENSIONS],
    [AC_USE_SYSTEM_EXTENSIONS],
    [AC_GNU_SOURCE])

AM_INIT_AUTOMAKE([-Wall -Wno-portability foreign subdir-objects tar-pax
                  parallel-tests])

AM_PROG_CC_C_O

m4_ifdef([AM_PROG_AR], [AM_PROG_AR])

AC_DISABLE_STATIC
AC_PROG_INSTALL
LT_INIT
LT_LIB_DLLOAD
AC_CONFIG_MACRO_DIR([m4])
AM_CONDITIONAL([GIT_CHECKOUT], [git log -1 >/dev/null 2>&1])
m4_ifdef([AM_SILENT_RULES], [AM_SILENT_RULES])
AM_CONDITIONAL([HAVE_GCC], [test "$ac_cv_prog_gcc" = yes])
AC_CHECK_HEADERS(stdint.h dlfcn.h)
AC_CONFIG_HEADER(config.h)
AC_CHECK_TYPES([errno_t], [], [], [[#include <errno.h>]])

#Check for endian headers
AC_CHECK_HEADERS([endian.h sys/endian.h byteswap.h])

AC_C_BIGENDIAN([AC_DEFINE(HAVE_BIG_ENDIAN, [1], [whether platform is big endian])],
               [AC_DEFINE(HAVE_LITTLE_ENDIAN, [1], [whether platform is little endian])])

m4_include([m4/build_macros.m4])
m4_include([m4/pkg.m4])
m4_include([m4/libtalloc.m4])
m4_include([m4/crypto.m4])
m4_include([m4/libpopt.m4])

AM_CHECK_LIBCRYPTO

AC_CONFIG_FILES([Makefile])

AC_OUTPUT
