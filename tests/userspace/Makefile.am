AUTOMAKE_OPTIONS = subdir-objects

dist_check_SCRIPTS = verify-passphrase-sig.sh
check_PROGRAMS = verify-passphrase-sig/test

dist_noinst_DATA = tests.rc

if ENABLE_TESTS
## tests not suitable for make check go here
dist_noinst_SCRIPTS = 
noinst_PROGRAMS =
endif

verify_passphrase_sig_test_SOURCES = verify-passphrase-sig/test.c
verify_passphrase_sig_test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

TESTS = verify-passphrase-sig.sh

