#!/bin/sh -e

# Create and sign a release tarball for upload to
# https://launchpad.net/ecryptfs/trunk

error() {
	echo "ERROR: $@"
	exit 1
}

head -n1 debian/changelog | grep -i "unreleased" || error "This version must be 'unreleased'"


rm -f ./ecryptfs-utils*.tar.*
autoreconf -i -v -f
intltoolize --force
./configure --prefix=/usr
make dist
for i in `ls ecryptfs-utils-*.tar.gz`; do
	VER=`echo $i | sed 's/^.*-//' | sed 's/\..*$//'`
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
echo "  lp-project-upload ecryptfs-utils $VER ../ecryptfs-utils_$VER.orig.tar.gz $VER" "$changelog" /dev/null
echo
echo " dch --release released"
echo " debcommit --release"
NEXT_VER=$((VER+1))
echo " sed -i -e 's/AC_INIT..ecryptfs-utils.,.$VER.)/AC_INIT([ecryptfs-utils],[$NEXT_VER])/' configure.ac"
echo " dch -v '$NEXT_VER' 'UNRELEASED'"
echo " bzr commit -m 'opening $NEXT_VER'"
echo " bzr push lp:ecryptfs"
echo
