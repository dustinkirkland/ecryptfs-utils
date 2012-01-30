AUTOMAKE_OPTIONS = subdir-objects

noinst_SCRIPTS = lp-885744.sh miscdev-bad-count.sh extend-file-random.sh trunc-file.sh \
		 directory-concurrent.sh

noinst_PROGRAMS = miscdev-bad-count/test \
		  extend-file-random/test \
		  trunc-file/test \
		  directory-concurrent/test

miscdev_bad_count_test_SOURCES = miscdev-bad-count/test.c
miscdev_bad_count_test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

extend_file_random_test_SOURCES = extend-file-random/test.c

trunc_file_test_SOURCES = trunc-file/test.c

directory_concurrent_test_SOURCES = directory-concurrent/test.c
