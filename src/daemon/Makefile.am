bin_PROGRAMS=ecryptfsd

ecryptfsd_SOURCES = main.c
ecryptfsd_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS) $(KEYUTILS_CFLAGS)
ecryptfsd_LDADD = $(top_srcdir)/src/libecryptfs/libecryptfs.la $(KEYUTILS_LIBS) $(LIBGCRYPT_LIBS)
