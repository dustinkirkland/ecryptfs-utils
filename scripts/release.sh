#!/bin/sh -e

# Create and sign a release tarball for upload to
# https://launchpad.net/ecryptfs/trunk

./scripts/bootstrap.sh
./configure --prefix=/usr
make dist
for i in `ls ecryptfs-utils-*.tar.gz`; do
	ver=`echo $i | sed 's/^.*-//' | sed 's/\..*$//'`
	mv $i ecryptfs-utils_$ver.orig.tar.gz
done
gpg --armor --sign --detach-sig ecryptfs-utils_*.orig.tar.gz
