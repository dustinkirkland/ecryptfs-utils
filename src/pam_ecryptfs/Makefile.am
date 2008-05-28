if BUILD_PAM
pam_LTLIBRARIES = libpam_ecryptfs.la

install-data-hook:
	rm -f "$(DESTDIR)$(pamdir)/libpam_ecryptfs.la"
	rm -f "$(DESTDIR)$(pamdir)/libpam_ecryptfs.a"
	mv -f "$(DESTDIR)$(pamdir)/libpam_ecryptfs.so" "$(DESTDIR)$(pamdir)/pam_ecryptfs.so"
endif

libpam_ecryptfs_la_SOURCES = pam_ecryptfs.c
libpam_ecryptfs_la_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
libpam_ecryptfs_la_LIBADD = $(top_srcdir)/src/libecryptfs/libecryptfs.la $(PAM_LIBS) $(LIBGCRYPT_LIBS)
libpam_ecryptfs_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version
