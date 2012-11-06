#!/bin/sh -e
./scripts/release.sh --nosign
upstream=$(basename $PWD)
cd ..
rm -rf ubuntu
mkdir ubuntu
mv ecryptfs-utils*.orig.tar.gz* ubuntu
cd ubuntu
tar zxvf *.orig.tar.gz
cd ecryptfs-utils*/
cp -a ../../${upstream}/debian .
debuild -uc -us
