MAINTAINERCLEANFILES = $(srcdir)/Makefile.in

lib_LTLIBRARIES = libecryptfs.la

pkgconfig_DATA = libecryptfs.pc

libecryptfs_la_SOURCES = \
	main.c \
	messaging.c \
	packets.c \
	miscdev.c \
	sysfs.c \
	key_management.c \
	decision_graph.c \
	cmd_ln_parser.c \
	module_mgr.c \
	key_mod.c \
	ecryptfs-stat.c \
	$(top_srcdir)/src/key_mod/ecryptfs_key_mod_passphrase.c

libecryptfs_la_LDFLAGS = \
	-version-info @LIBECRYPTFS_LT_CURRENT@:@LIBECRYPTFS_LT_REVISION@:@LIBECRYPTFS_LT_AGE@ \
	-no-undefined
libecryptfs_la_CFLAGS = $(AM_CFLAGS) $(CRYPTO_CFLAGS) $(KEYUTILS_CFLAGS)
libecryptfs_la_LIBADD = $(CRYPTO_LIBS) $(KEYUTILS_LIBS)

splint:
	splint -warnposix -preproc -unrecog -predboolint -boolops +matchanyintegral *.c
