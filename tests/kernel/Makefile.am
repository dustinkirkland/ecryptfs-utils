AUTOMAKE_OPTIONS = subdir-objects

dist_noinst_DATA = tests.rc

dist_noinst_SCRIPTS = directory-concurrent.sh \
		      enospc.sh \
		      extend-file-random.sh \
		      file-concurrent.sh \
		      inode-race-stat.sh \
		      inotify.sh \
		      link.sh \
		      llseek.sh \
		      lp-1009207.sh \
		      lp-469664.sh \
		      lp-509180.sh \
		      lp-524919.sh \
		      lp-561129.sh \
		      lp-613873.sh \
		      lp-745836.sh \
		      lp-870326.sh \
		      lp-872905.sh \
		      lp-885744.sh \
		      lp-911507.sh \
		      lp-926292.sh \
		      lp-994247.sh \
		      miscdev-bad-count.sh \
		      mknod.sh \
		      mmap-bmap.sh \
		      mmap-close.sh \
		      mmap-dir.sh \
		      read-dir.sh \
		      setattr-flush-dirty.sh \
		      trunc-file.sh

if ENABLE_TESTS
noinst_PROGRAMS = directory-concurrent/test \
		  enospc/test \
		  extend-file-random/test \
		  file-concurrent/test \
		  inode-race-stat/test \
		  inotify/test \
		  llseek/test \
		  lp-509180/test \
		  lp-524919/test \
		  lp-870326/test \
		  lp-994247/test \
		  miscdev-bad-count/test \
		  mmap-bmap/test \
		  mmap-close/test \
		  mmap-dir/test \
		  read-dir/test \
		  trunc-file/test \
		  xattr/test
endif

directory_concurrent_test_SOURCES = directory-concurrent/test.c

enospc_test_SOURCES = enospc/test.c

extend_file_random_test_SOURCES = extend-file-random/test.c

file_concurrent_test_SOURCES = file-concurrent/test.c

inode_race_stat_test_SOURCES = inode-race-stat/test.c

inotify_test_SOURCES = inotify/test.c

llseek_test_SOURCES = llseek/test.c

lp_509180_test_SOURCES = lp-509180/test.c

lp_524919_test_SOURCES = lp-524919/test.c

lp_870326_test_SOURCES = lp-870326/test.c

lp_994247_test_SOURCES = lp-994247/test.c

miscdev_bad_count_test_SOURCES = miscdev-bad-count/test.c
miscdev_bad_count_test_LDADD = $(top_builddir)/src/libecryptfs/libecryptfs.la

mmap_bmap_test_SOURCES = mmap-bmap/test.c

mmap_close_test_SOURCES = mmap-close/test.c

mmap_dir_test_SOURCES = mmap-dir/test.c

read_dir_test_SOURCES = read-dir/test.c

trunc_file_test_SOURCES = trunc-file/test.c

xattr_test_SOURCES = xattr/test.c

