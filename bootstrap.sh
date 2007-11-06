#!/bin/sh

# Run this script on a fresh checkout from the repository, or if your
# distro's build environment chokes

autoreconf -i -v -f
libtoolize --copy --force
aclocal
autoconf
automake
