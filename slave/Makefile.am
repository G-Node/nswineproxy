NULL = 
ACLOCAL_AMFLAGS = -I m4 ${ACLOCAL_FLAGS}
AM_CFLAGS = -Wall 
INCLUDES = 	-I$(top_srcdir)/../common \
		-I$(top_srcdir)/common \
		$(NULL)

CC=$(CROSSCC)

neurosharelibs_PROGRAMS=nswineslave.exe

nswineslave_exe_LDADD = -lws2_32
nswineslave_exe_SOURCES = \
	$(top_srcdir)/common/nsWireProtocol.c \
	nswineslave.c \
	$(NULL)
