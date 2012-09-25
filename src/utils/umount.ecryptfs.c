/**
 * Copyright (C) 2009 International Business Machines
 * Author(s): Tyler Hicks <tyhicks@linux.vnet.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
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

#include <errno.h>
#include <mntent.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "ecryptfs.h"

static void usage()
{
	fprintf(stderr, "\teCryptfs umount helper\n\tusage: "
		"umount [ecryptfs mount point]\n"
		);
	exit(-EINVAL);
}

 /**
 * Parses a string of mount options, searching for an option name, and returns
 * a pointer to the option value.  For example, if name was "ecryptfs_sig=",
 * it would set value to a string containing the sig, up to the first
 * comma or NULL character in the mount options.  Name must end with an = sign.
 * value must be freed by the caller.
 */
static int get_mount_opt_value(char *mnt_opts, char *name, char **value)
{
	char *name_start, *val_start, *val_stop;
	size_t name_len, val_len;
	int rc = 0;

	name_len = strlen(name);
	if (name[name_len - 1] != '=') {
		rc = EINVAL;
		goto out;
	}

	name_start = strstr(mnt_opts, name);
	if (!name_start) {
		rc = EINVAL;
		goto out;
	}

	val_start = name_start + name_len;
	val_stop = strstr(val_start, ",");
	if (!val_stop)
		val_stop = mnt_opts + strlen(mnt_opts);

	val_len = val_stop - val_start;
	*value = malloc(val_len + 1);
	if (!(*value)) {
		rc = ENOMEM;
		goto out;
	}
	memcpy(*value, val_start, val_len);
	(*value)[val_len] = '\0';
out:
	return rc;
}

static int unlink_keys_from_keyring(const char *mnt_point)
{
	struct mntent *mntent;
	FILE *file;
	char *fekek_sig = NULL, *fnek_sig = NULL;
	int fekek_fail = 0, fnek_fail = 0;
	int rc;

	file = setmntent("/etc/mtab", "r");
	if (!file) {
		rc = EINVAL;
		goto out;
	}
	while ((mntent = getmntent(file))) {
		if (strcmp("ecryptfs", mntent->mnt_type))
			continue;
		if (strcmp(mnt_point, mntent->mnt_dir))
			continue;
		break;
	}
	if (!mntent) {
		rc = EINVAL;
		goto end_out;
	}
	if (!hasmntopt(mntent, "ecryptfs_unlink_sigs")) {
		rc = 0;
		goto end_out;
	}
	rc = get_mount_opt_value(mntent->mnt_opts, "ecryptfs_sig=", &fekek_sig);
	if (!rc) {
		fekek_fail = ecryptfs_remove_auth_tok_from_keyring(fekek_sig);
		if (fekek_fail == ENOKEY)
			fekek_fail = 0;
		if (fekek_fail)
			fprintf(stderr, "Failed to remove fekek with sig [%s] "
				"from keyring: %s\n", fekek_sig,
				strerror(fekek_fail));
	} else {
		fekek_fail = rc;
	}
	if (!get_mount_opt_value(mntent->mnt_opts,
				 "ecryptfs_fnek_sig=", &fnek_sig)
	    && strcmp(fekek_sig, fnek_sig)) {
		fnek_fail = ecryptfs_remove_auth_tok_from_keyring(fnek_sig);
		if (fnek_fail == ENOKEY)
			fnek_fail = 0;
		if (fnek_fail) {
			fprintf(stderr, "Failed to remove fnek with sig [%s] "
				"from keyring: %s\n", fnek_sig, 
				strerror(fnek_fail));
		}
	}
	free(fekek_sig);
	free(fnek_sig);
end_out:
	endmntent(file);
out:
	return (fekek_fail ? fekek_fail : (fnek_fail ? fnek_fail : rc));
}

static int construct_umount_args(int argc, char **argv, char ***new_argv)
{
	int new_argc = argc + 1;
	int i, rc;

	*new_argv = malloc(sizeof(char *) * (new_argc + 1));
	if (!*new_argv) {
		rc = errno;
		goto out;
	}
	(*new_argv)[0] = "umount";
	(*new_argv)[1] = "-i";
	for (i = 2; i < new_argc; i++)
		(*new_argv)[i] = argv[i - 1];
	(*new_argv)[i] = NULL;
	rc = 0;
out:
	return rc;
}

#define UMOUNT_PATH	"/bin/umount"
int main(int argc, char **argv)
{
	char **new_argv;
	int rc;

	if (argc<2)
		usage();

	if (unlink_keys_from_keyring(argv[1]))
		fprintf(stderr, "Could not unlink the key(s) from your keying. "
			"Please use `keyctl unlink` if you wish to remove the "
			"key(s). Proceeding with umount.\n");
	rc = construct_umount_args(argc, argv, &new_argv);
	if (rc) {
		fprintf(stderr, "Failed to construct umount arguments: %s\n",
			strerror(rc));
		goto out;
	}
	rc = execv(UMOUNT_PATH, new_argv);
	if (rc < 0) {
		rc = errno;
		fprintf(stderr, "Failed to execute %s: %m\n", UMOUNT_PATH);
		goto free_out;
	}
	rc = 0;
free_out:
	free(new_argv);
out:
	return rc;
}

