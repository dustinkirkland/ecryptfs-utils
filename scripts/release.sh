#!/bin/sh -e

# Create and sign a release tarball for upload to
# https://launchpad.net/ecryptfs/trunk

rm -f ./ecryptfs-utils*.tar.*
./scripts/bootstrap.sh
./configure --prefix=/usr
make dist
for i in `ls ecryptfs-utils-*.tar.gz`; do
	ver=`echo $i | sed 's/^.*-//' | sed 's/\..*$//'`
	mv $i ecryptfs-utils_$ver.orig.tar.gz
done
gpg --armor --sign --detach-sig ecryptfs-utils_*.orig.tar.gz
echo
echo "TO MAKE THE RELEASE OFFICIAL, UPLOAD:"
echo -n "  "
ls *.orig.tar.gz
echo "---->  https://launchpad.net/ecryptfs/trunk"
echo
