NULL = 
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CFLAGS = -std=c99 -Wall -Wmissing-prototypes -Wwrite-strings -fPIC -DPIC
INCLUDES = -I$(top_srcdir)/../common -I$(top_srcdir)/common $(glib_CFLAGS)

neurosharelibs_PROGRAMS=nsWineLibrary.so

nsWineLibrary_so_LDADD = $(glib_LIBS)
nsWineLibrary_so_LDFLAGS = -module -avoid-version -shared
nsWineLibrary_so_SOURCES = \
	ns-wine-library.c  \
	wire-iclient.c     \
	$(NULL)