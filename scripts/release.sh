#!/bin/sh -e

# Create and sign a release tarball for upload to
# https://launchpad.net/ecryptfs/trunk

error() {
	echo "ERROR: $@"
	exit 1
}

head -n1 debian/changelog | grep "unreleased" || error "This version must be 'unreleased'"


rm -f ./ecryptfs-utils*.tar.*
./scripts/bootstrap.sh
./configure --prefix=/usr
make dist
for i in `ls ecryptfs-utils-*.tar.gz`; do
	ver=`echo $i | sed 's/^.*-//' | sed 's/\..*$//'`
	mv $i ../ecryptfs-utils_$ver.orig.tar.gz
	rm -f ecryptfs-utils-*.tar.bz2
done

[ "$1" = "--nosign" ] && exit 0

curver=`head -n1 debian/changelog | sed "s/^.*(//" | sed "s/).*$//"`
bzr tag --delete $curver || true
bzr tag $curver
#ver=`expr $curver + 1`
#dch -v "$ver" "UNRELEASED"
#sed -i "s/$ver) jaunty;/$ver) unreleased;/" debian/changelog


gpg --armor --sign --detach-sig ../ecryptfs-utils_*.orig.tar.gz
echo
echo "TO MAKE THE RELEASE OFFICIAL, UPLOAD:"
echo -n "  "
ls ../ecryptfs-utils*.orig.tar.gz
echo "---->  https://launchpad.net/ecryptfs/trunk"
echo
