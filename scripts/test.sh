#!/bin/sh

source ./current-version.sh
if test "x$ECRYPTFS_VERSION" == "x"; then
        ECRYPTFS_VERSION="2.6.18-rc4-mm2"
fi
echo $ECRYPTFS_VERSION
