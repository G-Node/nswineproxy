NULL = 
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CFLAGS = -std=c99 -Wall -Wmissing-prototypes -Wwrite-strings -fPIC -DPIC
INCLUDES = 	-I$(top_srcdir)/../common \
		-I$(top_srcdir)/common \
	 	$(glib_CFLAGS) \
		$(gio_CFLAGS) \
		$(gthread_CFLAGS) \
		$(NULL)

test_prgs =			\
	test-message            \
	$(NULL)	

check_PROGRAMS = $(test_prgs)

TESTS =  $(test_prgs)

test_message_SOURCES = test-message.c $(top_srcdir)/common/nsWireProtocol.c
test_message_LDADD = $(glib_LIBS) $(gio_LIBS) $(gthread_LIBS)


