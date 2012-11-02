/*
 * Copyright (C) 2006 International Business Machines Corp.
 * Author: Mike Halcrow <mhalcrow@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of version 2 of the GNU General Public
 * License as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#endif
#include <string.h>
#include <errno.h>
#include <mntent.h>
#include <stdlib.h>
#include "../include/ecryptfs.h"

static int get_sysfs_mountpoint(char *mnt, int *mnt_size)
{
	FILE *fp;
	struct mntent *mntent;
	int rc;

	fp = fopen("/etc/mtab", "r");
	if (!fp) {
		rc = -errno;
		goto out;
	}
	while ((mntent = getmntent(fp)))
		if (strcmp(mntent->mnt_type, "sysfs") == 0) {
			*mnt_size = strlen(mntent->mnt_dir);
			if (mnt)
				memcpy(mnt, mntent->mnt_dir, *mnt_size);
			rc = 0;
			fclose(fp);
			goto out;
		}
	fclose(fp);
	/* Default to /sys if not found in /etc/mtab */
	*mnt_size = strlen("/sys");
	if (mnt)
		memcpy(mnt, "/sys", strlen("/sys"));
	rc = 0;
out:
	return rc;
}

int ecryptfs_get_version(uint32_t *version)
{
	char *mnt;
	char *handle;
	char version_str[16];
	ssize_t size;
	int mnt_size;
	int fd;
	int rc;

	rc = get_sysfs_mountpoint(NULL, &mnt_size);
	if (rc)
		goto out;
	mnt = malloc(mnt_size + 1);
	if (!mnt) {
		rc = -ENOMEM;
		goto out;
	}
	rc = get_sysfs_mountpoint(mnt, &mnt_size);
	if (rc) {
		free(mnt);
		goto out;
	}
	mnt[mnt_size] = '\0';
	rc = asprintf(&handle, "%s/fs/ecryptfs/version", mnt);
	free(mnt);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	fd = open(handle, O_RDONLY);
	/* We can attempt to modprobe ecryptfs, which might help if we're
	 * being called by code running as root
	 */
	if (fd == -1 && errno == ENOENT &&
	    system("/sbin/modprobe ecryptfs 2>/dev/null") != -1)
		fd = open(handle, O_RDONLY);
	free(handle);
	if (fd == -1) {
		rc = -EINVAL;
		goto out;
	}
	size = read(fd, version_str, 16);
	close(fd);
	if (size == -1 || size == 0) {
		rc = -EINVAL;
		goto out;
	}
	*version = atoi(version_str);
out:
	return rc;
}

struct ecryptfs_version_str_map_elem {
	uint32_t flag;
	char *str;
} ecryptfs_version_str_map[] = {
	{ECRYPTFS_VERSIONING_PASSPHRASE, "passphrase"},
	{ECRYPTFS_VERSIONING_PUBKEY, "Userspace daemon support"},
	{ECRYPTFS_VERSIONING_PLAINTEXT_PASSTHROUGH, "plaintext passthrough"},
	{ECRYPTFS_VERSIONING_POLICY, "policy"},
	{ECRYPTFS_VERSIONING_XATTR, "metadata in extended attribute"},
	{ECRYPTFS_VERSIONING_MISCDEV, "/dev/ecryptfs daemon interface"},
	{ECRYPTFS_VERSIONING_HMAC, "hmac"},
	{ECRYPTFS_VERSIONING_FILENAME_ENCRYPTION, "filename encryption"},
	{ECRYPTFS_VERSIONING_GCM, "gcm cipher block chaining"},
};

/**
 * positive on yes; zero on no
 */
int ecryptfs_supports_passphrase(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_PASSPHRASE);
}

int ecryptfs_supports_pubkey(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_PUBKEY);
}

int ecryptfs_supports_plaintext_passthrough(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_PLAINTEXT_PASSTHROUGH);
}

int ecryptfs_supports_hmac(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_HMAC);
}

int ecryptfs_supports_filename_encryption(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_FILENAME_ENCRYPTION);
}

int ecryptfs_supports_policy(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_POLICY);
}

int ecryptfs_supports_xattr(uint32_t version)
{
	return (version & ECRYPTFS_VERSIONING_XATTR);
}
