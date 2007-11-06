#!/bin/sh

todaysdate=`date +%Y%m%d`
ecryptfs_target_dir="ecryptfs-$todaysdate"
ecryptfs_util_dir="ecryptfs-utils-git"
ecryptfs_kernel_dir="ecryptfs-kernel-git"
rm -rf $ecryptfs_target_dir
mkdir $ecryptfs_target_dir
cp -Rv $ecryptfs_util_dir $ecryptfs_target_dir/ecryptfs-util
cp -Rv $ecryptfs_kernel_dir $ecryptfs_target_dir/ecryptfs-kernel
cd $ecryptfs_target_dir
cp ecryptfs-util/scripts/make.sh ./install.sh
cd ecryptfs-util
./scripts/delete-cruft.sh
rm autom4te.cache/*
aclocal || exit 1
libtoolize --force -c || exit 1
automake --add-missing -c || exit 1
autoconf || exit 1
cd ../ecryptfs-kernel
rm -f src
rm -f autom4te.cache/*
aclocal || exit 1
libtoolize --force -c || exit 1
ln -s 2.6.17 src
automake --add-missing -c || exit 1
autoconf || exit 1
rm -f src
rm Makefile
rm 2.6*/Makefile
rm -rf .git
find . -name ".libs" -exec rm -rf {} \;
find . -name ".deps" -exec rm -rf {} \;
find . -name ".tmp_versions" -exec rm -rf {} \;
find . -name "*.ko" -exec rm -rf {} \;
find . -name "*.o" -exec rm -rf {} \;
find . -name "*.orig" -exec rm -rf {} \;
find . -name "*.mod.c" -exec rm -rf {} \;
find . -name "*.symvers" -exec rm -rf {} \;
find . -name "*~" -exec rm -rf {} \;
find . -name ".[a-z]*" -exec rm -rf {} \;
find . -name "*.rej" -exec rm -rf {} \;
find . -name "out.txt" -exec rm -rf {} \;
find . -name ".dotest" -exec rm -rf {} \;
cd ../..
tar cjvf $ecryptfs_target_dir.tar.bz2 $ecryptfs_target_dir
rm -rf $ecryptfs_target_dir
