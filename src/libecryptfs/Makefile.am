lib_LTLIBRARIES = libecryptfs.la
pkgconfig_DATA=libecryptfs.pc

libecryptfs_la_SOURCES = \
	main.c \
	cipher_list.c \
	netlink.c \
	netlink_packets.c \
	sysfs.c \
	key_management.c \
	decision_graph.c \
	cmd_ln_parser.c \
	module_mgr.c \
	key_mod.c \
	$(top_srcdir)/src/key_mod/ecryptfs_key_mod_passphrase.c
libecryptfs_la_LDFLAGS = \
	-version-info @LIBECRYPTFS_LT_CURRENT@:@LIBECRYPTFS_LT_REVISION@:@LIBECRYPTFS_LT_AGE@ \
	-no-undefined
libecryptfs_la_CFLAGS = $(AM_CFLAGS) $(LIBGCRYPT_CFLAGS) $(KEYUTILS_CFLAGS)
libecryptfs_la_LIBADD = $(LIBGCRYPT_LIBS) $(KEYUTILS_LIBS)

splint:
	splint -warnposix -preproc -unrecog -predboolint -boolops +matchanyintegral *.c
