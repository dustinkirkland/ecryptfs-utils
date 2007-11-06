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
libecryptfs_key_mod_openssl_la_LDFLAGS = $(OPENSSL_LIBS)
libecryptfs_key_mod_openssl_la_CFLAGS = $(AM_CFLAGS) $(OPENSSL_CFLAGS)

libecryptfs_key_mod_pkcs11_helper_la_SOURCES = ecryptfs_key_mod_pkcs11_helper.c
libecryptfs_key_mod_pkcs11_helper_la_CFLAGS = $(AM_CFLAGS) $(PKCS11_HELPER_CFLAGS) $(OPENSSL_CFLAGS)
libecryptfs_key_mod_pkcs11_helper_la_LIBADD = $(PKCS11_HELPER_LIBS) $(OPENSSL_LIBS)

libecryptfs_key_mod_tspi_la_SOURCES = ecryptfs_key_mod_tspi.c
libecryptfs_key_mod_tspi_la_CFLAGS = $(AM_CFLAGS) $(TSPI_CFLAGS)
libecryptfs_key_mod_tspi_la_LIBADD = $(TSPI_LIBS)

libecryptfs_key_mod_gpg_la_SOURCES = ecryptfs_key_mod_gpg.c
libecryptfs_key_mod_gpg_la_CFLAGS = $(AM_CFLAGS) $(GPGME_CFLAGS)
libecryptfs_key_mod_gpg_la_LIBADD = $(GPGME_LIBS)

libecryptfs_key_mod_passphrase_la_SOURCES = ecryptfs_key_mod_passphrase.c
libecryptfs_key_mod_passphrase_la_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS)
libecryptfs_key_mod_passphrase_la_LIBADD = $(LIBGCRYPT_LIBS)

install-data-hook:
	for f in `echo "$(ecryptfskeymod_LTLIBRARIES)" | $(SED) 's/\.la//g'`; do \
		rm -fr \
			"$(DESTDIR)$(ecryptfskeymoddir)/$$f.la" \
			"$(DESTDIR)$(ecryptfskeymoddir)/$$f.a" \
			"$(DESTDIR)$(ecryptfskeymoddir)/$$f.so" \
			"$(DESTDIR)$(ecryptfskeymoddir)/$$f.so.0"; \
		mv -f "$(DESTDIR)$(ecryptfskeymoddir)/$$f.so.0.0.0" "$(DESTDIR)$(ecryptfskeymoddir)/$$f.so" ; \
	done
