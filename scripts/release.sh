#!/bin/sh -e

# Create and sign a release tarball for upload to
# https://launchpad.net/ecryptfs/trunk

error() {
	echo "ERROR: $@"
	exit 1
}

head -n1 debian/changelog | grep -i "unreleased" || error "This version must be 'unreleased'"
curver=`head -n1 debian/changelog | sed "s/^.*(//" | sed "s/).*$//"`

rm -f ./ecryptfs-utils_$curver.orig.tar.gz
./autogen.sh
./configure --prefix=/usr
make dist
for i in `ls ecryptfs-utils-*.tar.gz`; do
	VER=`echo $i | sed 's/^.*-//' | sed 's/\..*$//'`
	mv $i ../ecryptfs-utils_$VER.orig.tar.gz
	rm -f ecryptfs-utils-*.tar.bz2
done

[ "$1" = "--nosign" ] && exit 0
gpg --armor --sign --detach-sig ../ecryptfs-utils_$curver.orig.tar.gz

bzr tag --delete $curver || true
bzr tag $curver

cd ..
tar zxvf ecryptfs-utils_$curver.orig.tar.gz
cd ecryptfs-utils-$curver
cp -a ../ecryptfs/debian .
dch -v "$curver-0ubuntu1" "precise"
debuild -S
nextver=$((curver+1))

echo
echo "TO MAKE THE RELEASE OFFICIAL, UPLOAD:"
echo -n "  "
echo "  lp-project-upload ecryptfs $curver ../ecryptfs-utils_$curver.orig.tar.gz $nextver" "$changelog" /dev/null
echo
echo " dch --release released"
echo " debcommit --release"
echo " sed -i -e 's/AC_INIT..ecryptfs-utils.,.$curver.)/AC_INIT([ecryptfs-utils],[$nextver])/' configure.ac"
echo " dch -v '$nextver' 'UNRELEASED'"
echo " bzr commit -m 'opening $nextver'"
echo " bzr push lp:ecryptfs"
echo
