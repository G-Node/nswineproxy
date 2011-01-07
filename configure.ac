AC_INIT([nswine], [0.0.1])

AC_CONFIG_SRCDIR([configure.ac])
AC_CONFIG_MACRO_DIR([m4])
AC_CONFIG_AUX_DIR([aux])

AM_INIT_AUTOMAKE([1.11 -Wno-portability])
AM_SANITY_CHECK

AC_PROG_INSTALL
AC_PROG_LN_S
AC_PATH_PROG(PKG_CONFIG, pkg-config, no)

m4_ifdef([AM_SILENT_RULES],[AM_SILENT_RULES([yes])])

AC_PROG_CC
AC_CHECK_PROGS(CROSSCC, i586-mingw32msvc-gcc i386-mingw32msvc-gcc i386-mingw32-gcc mingw-gcc mingw32-gcc, no)
if test "$CROSSCC" == "no"; then
   AC_MSG_ERROR([Could not find MinGW cross compiler])
fi

AC_ARG_WITH(neuroshare_libs_dir, [  --with-neuroshare-libs-dir=PATH choose directory for the Neuroshare libraries, [default=LIBDIR/neuroshare]], neurosharelibsdir="$withval", neurosharelibsdir=${libdir}/neuroshare)
AC_SUBST(neurosharelibsdir)

PKG_CHECK_MODULES(glib, glib-2.0 >= 2.24)
PKG_CHECK_MODULES(gio, gio-2.0 >= 2.24)
PKG_CHECK_MODULES(gthread, gthread-2.0 >= 2.24)

AC_CONFIG_FILES([
  library/Makefile
  slave/Makefile
  Makefile
])

AC_OUTPUT

