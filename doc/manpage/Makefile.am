# Copyright (C) 2006 Trevor Highland <trevor.highland@gmail.com>
#
# This file is free software; as a special exception the author gives
# unlimited permission to copy and/or distribute it, with or without
# modifications, as long as this notice is preserved.
#
# This program is distributed in the hope that it will be useful, but
# WITHOUT ANY WARRANTY, to the extent permitted by law; without even the
# implied warranty of MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.

MAINTAINERCLEANFILES = $(srcdir)/Makefile.in
DISTCLEANFILES = ecryptfs.7

dist_noinst_DATA = ecryptfs.pod
dist_man_MANS = \
	ecryptfs-manager.8 \
	mount.ecryptfs.8 \
	ecryptfsd.8 \
	ecryptfs.7

ecryptfs.7: $(srcdir)/ecryptfs.pod
	$(POD2MAN)					\
	--center="eCryptfs" --section=7			\
	--release=$(PACKAGE_VERSION) $(srcdir)/ecryptfs.pod > ecryptfs.7
