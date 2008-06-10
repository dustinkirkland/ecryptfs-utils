MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

ecryptfskeymod_LTLIBRARIES=libecryptfs_key_mod_passphrase.la

if BUILD_OPENSSL
ecryptfskeymod_LTLIBRARIES+=libecryptfs_key_mod_openssl.la
endif
if BUILD_PKCS11_HELPER
ecryptfskeymod_LTLIBRARIES+=libecryptfs_key_mod_pkcs11_helper.la
endif
if BUILD_TSPI
ecryptfskeymod_LTLIBRARIES+=libecryptfs_key_mod_tspi.la
endif
if BUILD_GPG
ecryptfskeymod_LTLIBRARIES+=libecryptfs_key_mod_gpg.la
endif

libecryptfs_key_mod_openssl_la_SOURCES = ecryptfs_key_mod_openssl.c
libecryptfs_key_mod_openssl_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)
libecryptfs_key_mod_openssl_la_LIBADD = $(OPENSSL_LIBS)
libecryptfs_key_mod_openssl_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libecryptfs_key_mod_pkcs11_helper_la_SOURCES = ecryptfs_key_mod_pkcs11_helper.c
libecryptfs_key_mod_pkcs11_helper_la_CFLAGS = $(AM_CFLAGS) $(PKCS11_HELPER_CFLAGS) $(OPENSSL_CFLAGS)
libecryptfs_key_mod_pkcs11_helper_la_LIBADD = $(PKCS11_HELPER_LIBS) $(OPENSSL_LIBS)
libecryptfs_key_mod_pkcs11_helper_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libecryptfs_key_mod_tspi_la_SOURCES = ecryptfs_key_mod_tspi.c
libecryptfs_key_mod_tspi_la_CFLAGS = $(AM_CFLAGS) $(TSPI_CFLAGS)
libecryptfs_key_mod_tspi_la_LIBADD = $(TSPI_LIBS)
libecryptfs_key_mod_tspi_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libecryptfs_key_mod_gpg_la_SOURCES = ecryptfs_key_mod_gpg.c
libecryptfs_key_mod_gpg_la_CFLAGS = $(AM_CFLAGS) $(GPGME_CFLAGS)
libecryptfs_key_mod_gpg_la_LIBADD = $(GPGME_LIBS)
libecryptfs_key_mod_gpg_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

libecryptfs_key_mod_passphrase_la_SOURCES = ecryptfs_key_mod_passphrase.c
libecryptfs_key_mod_passphrase_la_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
libecryptfs_key_mod_passphrase_la_LIBADD = $(LIBGCRYPT_LIBS)
libecryptfs_key_mod_passphrase_la_LDFLAGS = $(AM_LDFLAGS) -module -avoid-version -shared

# Needed until libtool-2
install-data-hook:	install-ecryptfskeymodLTLIBRARIES
	for f in `echo "$(ecryptfskeymod_LTLIBRARIES)" | $(SED) 's/\.la//g'`; do \
		rm -f "$(DESTDIR)$(ecryptfskeymoddir)/$$f.la"; \
		rm -f "$(DESTDIR)$(ecryptfskeymoddir)/$$f.a"; \
	done
uninstall-local:
	for f in `echo "$(ecryptfskeymod_LTLIBRARIES)" | $(SED) 's/\.la//g'`; do \
		rm -f "$(DESTDIR)$(ecryptfskeymoddir)/$$f.so"; \
	done
