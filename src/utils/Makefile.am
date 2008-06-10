MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

EXTRA_DIST=ecryptfsrc ecryptfs-setup-confidential ecryptfs-mount-confidential ecryptfs-umount-confidential

rootsbin_PROGRAMS=mount.ecryptfs
bin_PROGRAMS=ecryptfs-manager ecryptfs-wrap-passphrase \
	     ecryptfs-unwrap-passphrase \
	     ecryptfs-insert-wrapped-passphrase-into-keyring \
	     ecryptfs-rewrap-passphrase \
	     ecryptfs-add-passphrase ecryptfs-zombie-kill \
	     ecryptfs-zombie-list
bin_SCRIPTS = ecryptfs-setup-confidential \
	      ecryptfs-mount-confidential \
	      ecryptfs-umount-confidential
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
ecryptfs_zombie_kill_SOURCES = ecryptfs_zombie_kill.c
ecryptfs_zombie_kill_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
ecryptfs_zombie_list_SOURCES = ecryptfs_zombie_list.c
ecryptfs_zombie_list_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

ecryptfs_generate_tpm_key_SOURCES = ecryptfs_generate_tpm_key.c
ecryptfs_generate_tpm_key_CFLAGS = $(AM_CFLAGS) $(TSPI_CFLAGS)
ecryptfs_generate_tpm_key_LDADD = $(TSPI_LIBS)

test_SOURCES = test.c io.c
test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
