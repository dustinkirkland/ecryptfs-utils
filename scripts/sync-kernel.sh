#!/bin/sh

source ecryptfs-util-git/scripts/current-version.sh
echo
echo "Synchronizing linux-git code with ecryptfs-kernel-git code"
echo
rm -f linux-git/fs/ecryptfs/ecryptfs.mod.c
cp linux-git/fs/ecryptfs/*.[ch] ecryptfs-kernel-git/$ECRYPTFS_VERSION
cd ecryptfs-kernel-git
rm -rf 2.6.16
rm -rf 2.6.17
rm -rf 2.6.18
rm -rf src
mv $ECRYPTFS_VERSION src
patch -p1 < patches/netlink-hack.txt
mv src $ECRYPTFS_VERSION

cp -R $ECRYPTFS_VERSION src
patch -p1 < backpatches/ecryptfs-backpatch-$ECRYPTFS_VERSION-to-2.6.18.txt
mv src 2.6.18

cp -R $ECRYPTFS_VERSION src
patch -p1 < backpatches/ecryptfs-backpatch-$ECRYPTFS_VERSION-to-2.6.17.txt
mv src 2.6.17

cp -R $ECRYPTFS_VERSION src
patch -p1 < backpatches/ecryptfs-backpatch-$ECRYPTFS_VERSION-to-2.6.16.txt
mv src 2.6.16

cd ..
