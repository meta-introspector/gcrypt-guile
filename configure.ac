AC_INIT([Guile-Gcrypt], [0.2.1], [cwebber@dustycloud.org],
  [guile-gcrypt], [https://notabug.org/cwebber/guile-gcrypt])

AC_CONFIG_AUX_DIR([build-aux])
AC_CONFIG_MACRO_DIR([m4])

AM_INIT_AUTOMAKE([-Wall -Werror gnu])
AM_SILENT_RULES([yes])

dnl We require guile.m4, from Guile.  Make sure it's available.
m4_pattern_forbid([^GUILE_P])
m4_pattern_allow([^GUILE_PKG_ERRORS])

GUILE_PKG([3.0 2.2 2.0])
GUILE_PROGS

AC_CONFIG_FILES([Makefile gcrypt/package-config.scm])
AC_CONFIG_FILES([pre-inst-env], [chmod +x pre-inst-env])

dnl Prepare a version of $datadir that does not contain references to
dnl shell variables.  (Borrowed from Sly, which borrowed from Guix...)
guile_gcrypt_prefix="`eval echo $prefix | sed -e"s|NONE|/usr/local|g"`"
guile_gcrypt_datadir="`eval eval echo $datadir | sed -e "s|NONE|$guile_gcrypt_prefix|g"`"
AC_SUBST([guile_gcrypt_datadir])

LIBGCRYPT="libgcrypt"
LIBGCRYPT_LIBDIR="no"
LIBGCRYPT_PREFIX="no"

AC_ARG_WITH([libgcrypt-prefix],
  [AS_HELP_STRING([--with-libgcrypt-prefix=DIR], [search for GNU libgcrypt in DIR])],
  [case "$withval" in
    yes|no)
      ;;
    *)
      LIBGCRYPT="$withval/lib/libgcrypt"
      LIBGCRYPT_PREFIX="$withval"
      LIBGCRYPT_LIBDIR="$withval/lib"
      ;;
   esac])

AC_ARG_WITH([libgcrypt-libdir],
  [AS_HELP_STRING([--with-libgcrypt-libdir=DIR],
     [search for GNU libgcrypt's shared library in DIR])],
  [case "$withval" in
    yes|no)
      LIBGCRYPT="libgcrypt"
      LIBGCRYPT_LIBDIR="no"
      ;;
    *)
      LIBGCRYPT="$withval/libgcrypt"
      LIBGCRYPT_LIBDIR="$withval"
      ;;
   esac])

dnl If none of the --with-libgcrypt-* options was used, try to determine the
dnl absolute file name of libgcrypt.so.
case "x$LIBGCRYPT_PREFIX$LIBGCRYPT_LIBDIR" in
  xnono)
    GUIX_LIBGCRYPT_LIBDIR([LIBGCRYPT_LIBDIR])
    if test "x$LIBGCRYPT_LIBDIR" != x; then
      LIBGCRYPT="$LIBGCRYPT_LIBDIR/libgcrypt"
    else
      dnl 'config-daemon.ac' expects "no" in this case.
      LIBGCRYPT_LIBDIR="no"
    fi
    ;;
esac

dnl Library name suitable for `dynamic-link'.
AC_MSG_CHECKING([for libgcrypt shared library name])
AC_MSG_RESULT([$LIBGCRYPT])
AC_SUBST([LIBGCRYPT])
AC_SUBST([LIBGCRYPT_PREFIX])
AC_SUBST([LIBGCRYPT_LIBDIR])

if test "$cross_compiling" = "no"; then
   GUIX_ASSERT_LIBGCRYPT_USABLE
else
   GUILE_TARGET="--target=$host_alias"
   AC_SUBST([GUILE_TARGET])
fi

AC_OUTPUT
