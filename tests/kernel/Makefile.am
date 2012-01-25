AUTOMAKE_OPTIONS = subdir-objects

noinst_SCRIPTS = lp-885744.sh miscdev-bad-count.sh

noinst_PROGRAMS = miscdev-bad-count/test

miscdev_bad_count_test_SOURCES = miscdev-bad-count/test.c
miscdev_bad_count_test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la
