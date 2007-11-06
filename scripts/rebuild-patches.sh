#!/bin/sh

source ecryptfs-util-git/scripts/current-version.sh

cd ecryptfs-kernel-git/$ECRYPTFS_VERSION
rm -rf Makefile
rm -rf .tmp_versions
rm -rf .[a-z]*
rm -rf *.o
rm -rf *.ko
rm -rf *symvers
rm -rf *~
rm -rf *.cmd.c
rm -rf *.orig
rm -rf *.rej
cd ../..

cd ecryptfs-kernel-git/2.6.18
rm -rf Makefile
rm -rf .tmp_versions
rm -rf out.txt
rm -rf .[a-z]*
rm -rf *.o
rm -rf *.ko
rm -rf *symvers
rm -rf *~
rm -rf *.cmd.c
rm -rf *.orig
rm -rf *.rej
cd ../..

cd ecryptfs-kernel-git/2.6.17
rm -rf Makefile
rm -rf .tmp_versions
rm -rf out.txt
rm -rf .[a-z]*
rm -rf *.o
rm -rf *.ko
rm -rf *symvers
rm -rf *~
rm -rf *.cmd.c
rm -rf *.orig
rm -rf *.rej
cd ../..

cd ecryptfs-kernel-git/2.6.16
rm -rf Makefile
rm -rf .tmp_versions
rm -rf out.txt
rm -rf .[a-z]*
rm -rf *.o
rm -rf *.ko
rm -rf *symvers
rm -rf *~
rm -rf *.cmd.c
rm -rf *.orig
rm -rf *.rej
cd ../..

rm -rf ecryptfs-kernel-git-2.6.16/
cp -Rv ecryptfs-kernel-git/ ecryptfs-kernel-git-2.6.16/
cd ecryptfs-kernel-git-2.6.16/
rm -rf src
cp -Rv 2.6.16 src
cd ../ecryptfs-kernel-git/
rm -rf src
cp -Rv $ECRYPTFS_VERSION src
cd ..
rm -f tmp.txt
diff -Naur ecryptfs-kernel-git ecryptfs-kernel-git-2.6.16 > tmp.txt
mv tmp.txt ecryptfs-kernel-git/backpatches/ecryptfs-backpatch-$ECRYPTFS_VERSION-to-2.6.16.txt
rm -rf ecryptfs-kernel-git-2.6.16
cd ecryptfs-kernel-git/
rm -rf src
cd ..

rm -rf ecryptfs-kernel-git-2.6.18/
cp -Rv ecryptfs-kernel-git/ ecryptfs-kernel-git-2.6.18/
cd ecryptfs-kernel-git-2.6.18/
rm -rf src
cp -Rv 2.6.18 src
cd ../ecryptfs-kernel-git/
rm -rf src
cp -Rv $ECRYPTFS_VERSION src
cd ..
rm -f tmp.txt
diff -Naur ecryptfs-kernel-git ecryptfs-kernel-git-2.6.18 > tmp.txt
mv tmp.txt ecryptfs-kernel-git/backpatches/ecryptfs-backpatch-$ECRYPTFS_VERSION-to-2.6.18.txt
rm -rf ecryptfs-kernel-git-2.6.18
cd ecryptfs-kernel-git/
rm -rf src
cd ..

rm -rf ecryptfs-kernel-git-2.6.17/
cp -Rv ecryptfs-kernel-git/ ecryptfs-kernel-git-2.6.17/
cd ecryptfs-kernel-git-2.6.17/
rm -rf src
cp -Rv 2.6.17 src
cd ../ecryptfs-kernel-git/
rm -rf src
cp -Rv $ECRYPTFS_VERSION src
cd ..
rm -f tmp.txt
diff -Naur ecryptfs-kernel-git ecryptfs-kernel-git-2.6.17 > tmp.txt
mv tmp.txt ecryptfs-kernel-git/backpatches/ecryptfs-backpatch-$ECRYPTFS_VERSION-to-2.6.17.txt
rm -rf ecryptfs-kernel-git-2.6.17
cd ecryptfs-kernel-git/
rm -rf src
cd ..
