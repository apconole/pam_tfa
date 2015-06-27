#
# Copyright (C) 2015 Aaron Conole
# This file is part of pam_tfa
#
AC_INIT([pam_tfa], [0.2])
PACKAGE_RELDATE="2015-06-24"
AC_PREREQ([2.59])
AC_CONFIG_HEADERS([config.h])
AC_CONFIG_MACRO_DIR([m4])
AC_PROG_INSTALL
AM_INIT_AUTOMAKE([-Wall foreign])
AC_PROG_CC
AC_DISABLE_STATIC
AM_PROG_LIBTOOL
AC_PROG_LN_S

AC_ARG_WITH([pam-lib-dir], AS_HELP_STRING([--with-pam-lib-dir=PATH], 
                         [Path to the PAM Security lib directory [[/lib/security]]]), 
                         [PAMLIBDIR="$withval"], [PAMLIBDIR="/lib/security"])

regular_CFLAGS="-Wall -Werror -Wformat=2 -Waggregate-return -Wmissing-declarations -Wmissing-prototypes -Wredundant-decls -Wshadow -Wstrict-prototypes -pipe"
AC_ARG_ENABLE(gcov, AS_HELP_STRING([--enable-gcov], [Enable gcc profiling support]))

if test "x$enable_gcov" = "xyes"; then
   regular_CFLAGS="$regular_CFLAGS -fprofile-arcs -ftest-coverage"
fi

AC_SUBST([regular_CFLAGS])

AC_CHECK_HEADERS([curl/curl.h openssl/rand.h openssl/bio.h openssl/evp.h openssl/buffer.h])
AC_CHECK_FUNCS([gmtime_r setpwent getpwent endpwent setfsuid setfsgid strcat snprintf ])

PKG_CHECK_MODULES([libcurl], [libcurl >= 7.22.0])
PKG_CHECK_MODULES([libssl], [libssl >= 1.0.1])

AC_CHECK_HEADERS([security/pam_modules.h], [have_pamheader="yes"])

if test x"$have_pamheader" != x"yes"; then
   AC_MSG_ERROR([You are missing libpam development files])
fi

AC_CHECK_LIB(pam, pam_prompt,,PAM=no)
AC_CHECK_LIB(pam, pam_syslog,,PAM=no)
AC_CHECK_LIB(pam, pam_get_user,,PAM=no)

if test x"$PAM" = x"no" ; then
   AC_MSG_ERROR([You have an old or outdated PAM version])
fi

AC_SUBST(PAMLIBDIR)
AC_SUBST([PACKAGE_RELDATE])
AC_CONFIG_FILES([Makefile])
AC_OUTPUT
