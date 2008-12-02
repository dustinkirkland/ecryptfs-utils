#!/bin/sh -e

# Create and sign a release tarball for upload to
# https://launchpad.net/ecryptfs/trunk

./scripts/bootstrap.sh
./configure --prefix=/usr
make dist
gpg --armor --sign --detach-sig ecryptfs-utils-*.tar.gz
