MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

if BUILD_PAM
pam_LTLIBRARIES = pam_ecryptfs.la

# Needed until libtool-2
install-data-hook:	install-pamLTLIBRARIES
	rm -f "$(DESTDIR)$(pamdir)/pam_ecryptfs.la"
	rm -f "$(DESTDIR)$(pamdir)/pam_ecryptfs.a"
uninstall-local:
	rm -f "$(DESTDIR)$(pamdir)/pam_ecryptfs.so"
endif

pam_ecryptfs_la_SOURCES = pam_ecryptfs.c
pam_ecryptfs_la_CFLAGS = $(AM_CFLAGS)
pam_ecryptfs_la_LIBADD = $(top_builddir)/src/libecryptfs/libecryptfs.la $(PAM_LIBS)
pam_ecryptfs_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared
