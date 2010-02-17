MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST=ecryptfsrc ecryptfs-rewrite-file ecryptfs-setup-private ecryptfs-setup-swap ecryptfs-mount-private ecryptfs-umount-private ecryptfs-migrate-home

rootsbin_PROGRAMS=mount.ecryptfs \
		  umount.ecryptfs \
		  mount.ecryptfs_private
bin_PROGRAMS=ecryptfs-manager ecryptfs-wrap-passphrase \
	     ecryptfs-unwrap-passphrase \
	     ecryptfs-insert-wrapped-passphrase-into-keyring \
	     ecryptfs-rewrap-passphrase \
	     ecryptfs-add-passphrase \
	     ecryptfs-stat
bin_SCRIPTS = ecryptfs-setup-private \
	      ecryptfs-setup-swap \
	      ecryptfs-mount-private \
	      ecryptfs-umount-private \
	      ecryptfs-rewrite-file \
	      ecryptfs-migrate-home
bin2dir = $(bindir)

noinst_PROGRAMS=test

if ENABLE_TESTS
TESTS=test
endif

if BUILD_TSPI
bin_PROGRAMS+=ecryptfs-generate-tpm-key
endif

INCLUDES = -I$(top_srcdir)/src/include

mount_ecryptfs_SOURCES = mount.ecryptfs.c io.c io.h gen_key.c plaintext_decision_graph.c
mount_ecryptfs_CFLAGS = $(AM_CFLAGS) $(KEYUTILS_CFLAGS) $(LIBGCRYPT_CFLAGS)
mount_ecryptfs_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la $(KEYUTILS_LIBS) $(LIBGCRYPT_LIBS)
umount_ecryptfs_SOURCES = umount.ecryptfs.c
umount_ecryptfs_CFLAGS = $(AM_CFLAGS) $(KEYUTILS_CFLAGS)
umount_ecryptfs_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
ecryptfs_manager_SOURCES = manager.c io.c io.h gen_key.c
ecryptfs_manager_CFLAGS = $(AM_CFLAGS) $(KEYUTILS_CFLAGS) $(LIBGCRYPT_CFLAGS)
ecryptfs_manager_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la $(KEYUTILS_LIBS) $(LIBGCRYPT_LIBS)
ecryptfs_wrap_passphrase_SOURCES = ecryptfs_wrap_passphrase.c
ecryptfs_wrap_passphrase_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
ecryptfs_unwrap_passphrase_SOURCES = ecryptfs_unwrap_passphrase.c
ecryptfs_unwrap_passphrase_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
ecryptfs_insert_wrapped_passphrase_into_keyring_SOURCES = ecryptfs_insert_wrapped_passphrase_into_keyring.c
ecryptfs_insert_wrapped_passphrase_into_keyring_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
ecryptfs_rewrap_passphrase_SOURCES = ecryptfs_rewrap_passphrase.c
ecryptfs_rewrap_passphrase_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
ecryptfs_add_passphrase_SOURCES = ecryptfs_add_passphrase.c
ecryptfs_add_passphrase_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

ecryptfs_generate_tpm_key_SOURCES = ecryptfs_generate_tpm_key.c
ecryptfs_generate_tpm_key_CFLAGS = $(AM_CFLAGS) $(TSPI_CFLAGS)
ecryptfs_generate_tpm_key_LDADD = $(TSPI_LIBS)

mount_ecryptfs_private_SOURCES = mount.ecryptfs_private.c
mount_ecryptfs_private_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la $(KEYUTILS_LIBS)

ecryptfs_stat_SOURCES = ecryptfs-stat.c
ecryptfs_stat_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

test_SOURCES = test.c io.c
test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

install-exec-hook:	install-rootsbinPROGRAMS
	-rm -f "$(DESTDIR)/$(rootsbindir)/umount.ecryptfs_private"
	$(LN_S) "mount.ecryptfs_private" "$(DESTDIR)/$(rootsbindir)/umount.ecryptfs_private"
