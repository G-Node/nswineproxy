#!/bin/sh

set -e

if [ "$1" = "clean" ]; then
  rm -f aclocal.m4 configure config.* `find . -name Makefile.in` libtool
  rm -rf autom4te.cache m4 aux
  rm -rf INSTALL
  exit
fi

if automake-1.11 --version &> /dev/null; then
  automake_suffix='-1.11'
else
  automake_suffix=''
fi

touch README INSTALL

mkdir -p m4 aux
aclocal${automake_suffix} ${ACLOCAL_FLAGS} || exit $?
automake${automake_suffix} --add-missing --foreign || exit $?
autoconf || exit $?

CFLAGS=${CFLAGS=-ggdb -Werror}
LDFLAGS=${LDFLAGS=-Wl,-O1}
export CFLAGS LDFLAGS

if test -z "$NOCONFIGURE"; then
  ./configure "$@"
fi
