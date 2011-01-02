NULL = 
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CFLAGS = -std=c99 -Wall -Wmissing-prototypes -Wwrite-strings -fPIC -DPIC
INCLUDES = 	-I$(top_srcdir)/../common \
		-I$(top_srcdir)/common \
	 	$(glib_CFLAGS) \
		$(gio_CFLAGS) \
		$(gthread_CFLAGS) \
		-DG_LOG_DOMAIN=\"NsWineLib\"
		$(NULL)

neurosharelibs_PROGRAMS=nsWineLibrary.so

nsWineLibrary_so_LDADD = $(glib_LIBS) $(gio_LIBS) $(gthread_LIBS)
nsWineLibrary_so_LDFLAGS = -module -avoid-version -shared
nsWineLibrary_so_SOURCES = \
	../common/nsWireProtocol.c \
	ns-wine-library.c  \
	wire-iclient.c     \
	$(NULL)