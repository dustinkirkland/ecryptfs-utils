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
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#include "ecryptfs.h"

 /**
 * Parses a string of mount options, searching for an option name, and returns
 * a pointer to the option value.  For example, if name was "ecryptfs_sig=",
 * it would set value to a string containing the sig, up to the first
 * comma or NULL character in the mount options.  Name must end with an = sign.
 * value must be freed by the caller.
 *
 * Return value is non-zero upon error. If name is not found in mnt_opts, 0 
 * is returned and (*value) is NULL.
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
		(*value) = NULL;
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

static int get_sigs(const char *mnt_point, char **fekek_sig, char **fnek_sig)
{
	struct mntent *mntent;
	FILE *file;
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
		/* User didn't ask us to unlink keys, nothing to do */
		rc = 0;
		goto end_out;
	}
	rc = get_mount_opt_value(mntent->mnt_opts, "ecryptfs_sig=", fekek_sig);
	if (rc) {
		fprintf(stderr, "Failed to find fekek sig in mount options "
			"[%s]: %s\n", mntent->mnt_opts, strerror(rc));
		*fekek_sig = NULL;
	}
	rc = get_mount_opt_value(mntent->mnt_opts, "ecryptfs_fnek_sig=",
				 fnek_sig);
	if (rc) {
		fprintf(stderr, "Failed to find fnek sig in mount options "
			"[%s]: %s\n", mntent->mnt_opts, strerror(rc));
		*fnek_sig = NULL;
	}
	rc = 0;
end_out:
	endmntent(file);
out:
	return rc;
}

static int construct_umount_args(int argc, char **argv, char ***new_argv)
{
	int new_argc = argc + 1;
	int i, rc;

	/*
	 * new_argc is argc + 1 because we're inserting the -i arg 
	 * malloc(new_argc + 1) to end new_argv in a NULL pointer
	 */
	*new_argv = malloc(sizeof(char *) * (new_argc + 1));
	if (!new_argv) {
		rc = errno;
		goto out;
	}
	(*new_argv)[0] = "umount";
	(*new_argv)[1] = "-i";
	if (argc > 1)
		for (i = 2; i < new_argc; i++)
			(*new_argv)[i] = argv[i - 1];
	(*new_argv)[new_argc] = NULL;
	rc = 0;
out:
	return rc;
}

static int do_umount(char *umount, char **argv)
{
	pid_t pid;
	int mount_rc, rc;

	pid = fork();
	if (pid < 0) {
		rc = errno;
		fprintf(stderr, "Failed to fork process to execute umount: "
			"%m\n");
		goto out;
	} else if (!pid)
		if (execv(umount, argv) < 0) {
			fprintf(stderr, "Failed to execute umount: %m\n");
			exit(errno);
		}
	rc = waitpid(pid, &mount_rc, 0);
	if (rc < 0) {
		rc = errno;
		fprintf(stderr, "Failed to wait for umount to finish "
			"executing: %m\n");
		goto out;
	}
	if (mount_rc) {
		/* We'll let /sbin/umount tell the user why it failed */
		rc = mount_rc;
		goto out;
	}
	rc = 0;
out:
	return rc;
}

#define UMOUNT_PATH	"/bin/umount"
int main(int argc, char **argv)
{
	char **new_argv;
	char *fekek_sig = NULL;
	char *fnek_sig = NULL;
	int rc;

	if (argc > 1) {
		rc = get_sigs(argv[1], &fekek_sig, &fnek_sig);
		if (rc)
			fprintf(stderr, "Failed to retrieve key sigs for mount "
				"[%s]: %s\nProceeding with umount, use `keyctl "
				"unlink <key> @u` to remove keys manually\n",
				argv[1], strerror(rc));
	}
	rc = construct_umount_args(argc, argv, &new_argv);
	if (rc) {
		fprintf(stderr, "Failed to construct umount arguments: %s\n",
			strerror(rc));
		goto out;
	}
	rc = do_umount(UMOUNT_PATH, new_argv);
	if (rc < 0) {
		rc = errno;
		goto free_out;
	}
	if (fekek_sig) {
		rc = ecryptfs_remove_auth_tok_from_keyring(fekek_sig);
		if (rc)
			fprintf(stderr, "The umount was successful, but failed "
				"to unlink the fekek [%s] from your keying: "
				"%s\nPlease use `keyctl unlink <key> @u` if "
				"you wish to remove it manually.\n", fekek_sig,
				strerror(rc));
	}
	if (fnek_sig) {
		if (fekek_sig && !strcmp(fekek_sig, fnek_sig))
			goto out_success;
		rc = ecryptfs_remove_auth_tok_from_keyring(fnek_sig);
		if (rc)
			fprintf(stderr, "The umount was successful, but failed "
				"to unlink the fnek [%s] from your keying: %s\n"
				"Please use `keyctl unlink <key> @u` if you "
				"wish to remove it manually.\n", fnek_sig,
				strerror(rc));
	}
out_success:
	rc = 0;
free_out:
	free(new_argv);
out:
	free(fekek_sig);
	free(fnek_sig);
	return rc;
}

