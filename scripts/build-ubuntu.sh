#!/bin/sh
./scripts/release.sh --nosign
cd ..
rm -rf ubuntu
mkdir ubuntu
mv ecryptfs-utils*.orig.tar.gz* ubuntu
cd ubuntu
tar zxvf *.orig.tar.gz
cd ecryptfs-utils*/
cp -a ../../ecryptfs/debian .
debuild -uc -us
