# Copyright (C) 2006 Trevor Highland <trevor.highland@gmail.com>
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

EXTRA_DIST=ecryptfs.pod

man_MANS = ecryptfs.7
dist_man_MANS = \
	ecryptfs-manager.8 \
	mount.ecryptfs.8 \
	ecryptfsd.8

ecryptfs.7: ecryptfs.pod 
	$(POD2MAN)					\
	--center="eCryptfs" --section=7			\
	--release=$(PACKAGE_VERSION) ecryptfs.pod > ecryptfs.7

local-clean:
	-rm -fr ecryptfs.7
