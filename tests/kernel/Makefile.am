AUTOMAKE_OPTIONS = subdir-objects

noinst_SCRIPTS = lp-885744.sh miscdev-bad-count.sh extend-file-random.sh \
		 trunc-file.sh directory-concurrent.sh file-concurrent.sh \
		 mmap-dir.sh lp-926292.sh read-dir.sh setattr-flush-dirty.sh \
		 inode-race-stat.sh

noinst_PROGRAMS = miscdev-bad-count/test \
		  extend-file-random/test \
		  trunc-file/test \
		  directory-concurrent/test \
		  file-concurrent/test \
		  inotify/test \
		  mmap-dir/test \
		  read-dir/test \
		  inode-race-stat/test

miscdev_bad_count_test_SOURCES = miscdev-bad-count/test.c
miscdev_bad_count_test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

extend_file_random_test_SOURCES = extend-file-random/test.c

trunc_file_test_SOURCES = trunc-file/test.c

directory_concurrent_test_SOURCES = directory-concurrent/test.c

file_concurrent_test_SOURCES = file-concurrent/test.c

inotify_test_SOURCES = inotify/test.c

mmap_dir_test_SOURCES = mmap-dir/test.c

read_dir_test_SOURCES = read-dir/test.c

inode_race_stat_test_SOURCES = inode-race-stat/test.c
