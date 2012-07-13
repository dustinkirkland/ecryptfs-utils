/* -*- Mode: C; tab-width: 4; indent-tabs-mode: t; c-basic-offset: 4 -*-
 *
 * pam_ecryptfs.c: PAM module that sends the user's authentication
 * tokens into the kernel keyring.
 *
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
 *            Dustin Kirkland <kirkland@ubuntu.com>
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

#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <limits.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/fsuid.h>
#include <grp.h>
#include <fcntl.h>
#include <security/pam_modules.h>
#include <security/pam_ext.h>
#include "../include/ecryptfs.h"

#define PRIVATE_DIR "Private"

static void error(const char *msg)
{
	syslog(LOG_ERR, "pam_ecryptfs: errno = [%i]; strerror = [%m]\n", errno);
	switch (errno) {
	case ENOKEY:
		syslog(LOG_ERR, "pam_ecryptfs: %s: Requested key not available\n", msg);
		return;

	case EKEYEXPIRED:
		syslog(LOG_ERR, "pam_ecryptfs: %s: Key has expired\n", msg);
		return;

	case EKEYREVOKED:
		syslog(LOG_ERR, "pam_ecryptfs: %s: Key has been revoked\n", msg);
		return;

	case EKEYREJECTED:
		syslog(LOG_ERR, "pam_ecryptfs: %s: Key was rejected by service\n", msg);
		return;
	default:
		syslog(LOG_ERR, "pam_ecryptfs: %s: Unknown key error\n", msg);
		return;
	}
}

/* returns: 0 if file does not exist, 1 if it exists, <0 for error */
static int file_exists_dotecryptfs(const char *homedir, char *filename)
{
	char *file_path;
	int rc = 0;
	struct stat s;
	if (asprintf(&file_path, "%s/.ecryptfs/%s", homedir, filename) == -1)
		return -ENOMEM;
	if (stat(file_path, &s) != 0) {
		if (errno != ENOENT)
			rc = -errno;
		goto out;
	}
	rc = 1;
out:
	free(file_path);
	return rc;
}

static int wrap_passphrase_if_necessary(const char *username, uid_t uid, char *wrapped_pw_filename, char *passphrase, char *salt)
{
	char *unwrapped_pw_filename = NULL;
	struct stat s;
	int rc = 0;

	rc = asprintf(&unwrapped_pw_filename, "/dev/shm/.ecryptfs-%s", username);
	if (rc == -1) {
		syslog(LOG_ERR, "pam_ecryptfs: Unable to allocate memory\n");
		return -ENOMEM;
	}
	/* If /dev/shm/.ecryptfs-$USER exists and owned by the user
	   and ~/.ecryptfs/wrapped-passphrase does not exist
	   and a passphrase is set:
	   wrap the unwrapped passphrase file */
	if (stat(unwrapped_pw_filename, &s) == 0 && (s.st_uid == uid) &&
	    stat(wrapped_pw_filename, &s) != 0  &&
	    passphrase != NULL && *passphrase != '\0' &&
	    username != NULL && *username != '\0') {
		setuid(uid);
		rc = ecryptfs_wrap_passphrase_file(wrapped_pw_filename, passphrase, salt, unwrapped_pw_filename);
		if (rc != 0) {
			syslog(LOG_ERR, "pam_ecryptfs: Error wrapping cleartext password; " "rc = [%d]\n", rc);
		}
		return rc;
	}
	return 0;
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	uid_t uid = 0, oeuid = 0;
	long ngroups_max = sysconf(_SC_NGROUPS_MAX);
	gid_t gid = 0, oegid = 0, groups[ngroups_max+1];
	int ngids = 0;
	char *homedir = NULL;
	const char *username;
	char *passphrase = NULL;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	char *auth_tok_sig;
	char *private_mnt = NULL;
	pid_t child_pid, tmp_pid;
	long rc;

	rc = pam_get_user(pamh, &username, NULL);
	if (rc == PAM_SUCCESS) {
		struct passwd *pwd;

		pwd = getpwnam(username);
		if (pwd) {
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			homedir = pwd->pw_dir;
		}
	} else {
		syslog(LOG_ERR, "pam_ecryptfs: Error getting passwd info for user [%s]; rc = [%ld]\n", username, rc);
		goto out;
	}

	if ((oeuid = geteuid()) < 0 || (oegid = getegid()) < 0 ||
	    (ngids = getgroups(sizeof(groups)/sizeof(gid_t), groups)) < 0) {
		syslog(LOG_ERR, "pam_ecryptfs: geteuid error");
		goto outnouid;
	}

	if (setegid(gid) < 0 || setgroups(1, &gid) < 0 || seteuid(uid) < 0) {
		syslog(LOG_ERR, "pam_ecryptfs: seteuid error");
		goto out;
	}

	if (!file_exists_dotecryptfs(homedir, "auto-mount"))
		goto out;
	private_mnt = ecryptfs_fetch_private_mnt(homedir);
	if (ecryptfs_private_is_mounted(NULL, private_mnt, NULL, 1)) {
		syslog(LOG_DEBUG, "pam_ecryptfs: %s: %s is already mounted\n", __FUNCTION__, homedir);
		/* If private/home is already mounted, then we can skip
		   costly loading of keys */
		goto out;
	}
	if(file_exists_dotecryptfs(homedir, "wrapping-independent") == 1)
		rc = pam_prompt(pamh, PAM_PROMPT_ECHO_OFF, &passphrase, "Encryption passphrase: ");
	else
		rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&passphrase);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_ecryptfs: Error retrieving passphrase; rc = [%ld]\n",
		       rc);
		goto out;
	}
	auth_tok_sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "pam_ecryptfs: Out of memory\n");
		goto out;
	}
	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((child_pid = fork()) == 0) {
		/* temp regain uid 0 to drop privs */
		seteuid(oeuid);
		/* setgroups() already called */
		if (setgid(gid) < 0 || setuid(uid) < 0)
			goto out_child;

		if (passphrase == NULL) {
			syslog(LOG_ERR, "pam_ecryptfs: NULL passphrase; aborting\n");
			rc = -EINVAL;
			goto out_child;
		}
		if ((rc = ecryptfs_validate_keyring())) {
			syslog(LOG_WARNING, "pam_ecryptfs: Cannot validate keyring integrity\n");
		}
		rc = 0;
		if ((argc == 1)
		    && (memcmp(argv[0], "unwrap\0", 7) == 0)) {
			char *wrapped_pw_filename;
			char *unwrapped_pw_filename;
			struct stat s;

			rc = asprintf(
				&wrapped_pw_filename, "%s/.ecryptfs/%s",
				homedir,
				ECRYPTFS_DEFAULT_WRAPPED_PASSPHRASE_FILENAME);
			if (rc == -1) {
				syslog(LOG_ERR, "pam_ecryptfs: Unable to allocate memory\n");
				rc = -ENOMEM;
				goto out_child;
			}
			if (wrap_passphrase_if_necessary(username, uid, wrapped_pw_filename, passphrase, salt) == 0) {
				syslog(LOG_DEBUG, "pam_ecryptfs: Passphrase file wrapped");
			} else {
				goto out_child;
			}
			rc = ecryptfs_insert_wrapped_passphrase_into_keyring(
				auth_tok_sig, wrapped_pw_filename, passphrase,
				salt);
			free(wrapped_pw_filename);
		} else {
			rc = ecryptfs_add_passphrase_key_to_keyring(
				auth_tok_sig, passphrase, salt);
		}
		if (rc == 1) {
			goto out_child;
		}
		if (rc) {
			syslog(LOG_ERR, "pam_ecryptfs: Error adding passphrase key token to user session keyring; rc = [%ld]\n", rc);
			goto out_child;
		}
		if (fork() == 0) {
			if ((rc = ecryptfs_set_zombie_session_placeholder())) {
				syslog(LOG_ERR, "pam_ecryptfs: Error attempting to create and register zombie process; rc = [%ld]\n", rc);
			}
		}
out_child:
		free(auth_tok_sig);
		exit(0);
	}
	tmp_pid = waitpid(child_pid, NULL, 0);
	if (tmp_pid == -1)
		syslog(LOG_WARNING, "pam_ecryptfs: waitpid() returned with error condition\n");
out:

	seteuid(oeuid);
	setegid(oegid);
	setgroups(ngids, groups);

outnouid:
	if (private_mnt != NULL)
		free(private_mnt);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	return PAM_SUCCESS;
}

static struct passwd *fetch_pwd(pam_handle_t *pamh)
{
	long rc;
	const char *username = NULL;
	struct passwd *pwd = NULL;

	rc = pam_get_user(pamh, &username, NULL);
	if (rc != PAM_SUCCESS || username == NULL) {
		syslog(LOG_ERR, "pam_ecryptfs: Error getting passwd info for user [%s]; rc = [%ld]\n", username, rc);
		return NULL;
	}
	pwd = getpwnam(username);
	if (pwd == NULL) {
		syslog(LOG_ERR, "pam_ecryptfs: Error getting passwd info for user [%s]; rc = [%ld]\n", username, rc);
		return NULL;
	}
	return pwd;
}

static int private_dir(pam_handle_t *pamh, int mount)
{
	int rc, fd;
	struct passwd *pwd = NULL;
	char *sigfile = NULL;
	char *autofile = NULL;
	char *recorded = NULL;
	char *a;
	char *automount = "auto-mount";
	char *autoumount = "auto-umount";
	struct stat s;
	pid_t pid;
	struct utmp *u;
	int count = 0;

	if ((pwd = fetch_pwd(pamh)) == NULL) {
		/* fetch_pwd() logged a message */
		return 1;
	}
	if (mount == 1) {
		a = automount;
	} else {
		a = autoumount;
	}
	if (
	    (asprintf(&autofile, "%s/.ecryptfs/%s", pwd->pw_dir, a) < 0)
	     || autofile == NULL) {
		syslog(LOG_ERR, "pam_ecryptfs: Error allocating memory for autofile name");
		return 1;
        }
        if (
	    (asprintf(&sigfile, "%s/.ecryptfs/%s.sig", pwd->pw_dir,
	     PRIVATE_DIR) < 0) || sigfile == NULL) {
		syslog(LOG_ERR, "pam_ecryptfs: Error allocating memory for sigfile name");
		return 1;
        }
	if (stat(sigfile, &s) != 0) {
		/* No sigfile, no need to mount private dir */
		goto out;
	}
	if (!S_ISREG(s.st_mode)) {
		/* No sigfile, no need to mount private dir */
		goto out;
	}
	if ((pid = fork()) < 0) {
		syslog(LOG_ERR, "pam_ecryptfs: Error setting up private mount");
		return 1;
	}
	if (pid == 0) {
		if (mount == 1) {
		        if ((asprintf(&recorded,
			    "%s/.ecryptfs/.wrapped-passphrase.recorded",
			    pwd->pw_dir) < 0) || recorded == NULL) {
				syslog(LOG_ERR, "pam_ecryptfs: Error allocating memory for recorded name");
				exit(1);
			}
			if (stat(recorded, &s) != 0 && stat("/usr/share/ecryptfs-utils/ecryptfs-record-passphrase", &s) == 0) {
				/* User has not recorded their passphrase */
				unlink("/var/lib/update-notifier/user.d/ecryptfs-record-passphrase");
				symlink("/usr/share/ecryptfs-utils/ecryptfs-record-passphrase", "/var/lib/update-notifier/user.d/ecryptfs-record-passphrase");
				fd = open("/var/lib/update-notifier/dpkg-run-stamp", O_WRONLY|O_CREAT|O_NONBLOCK, 0666);
				close(fd);
			}
			if (stat(autofile, &s) != 0) {
				/* User does not want to auto-mount */
				syslog(LOG_DEBUG, "pam_ecryptfs: Skipping automatic eCryptfs mount");
				exit(0);
			}
			clearenv();
			if (setgroups(1, &pwd->pw_gid) < 0 || setgid(pwd->pw_gid) < 0)
				return -1;
			/* run mount.ecryptfs_private as the user */
			if (setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid) < 0)
				return -1;
			execl("/sbin/mount.ecryptfs_private",
			      "mount.ecryptfs_private", NULL);
		} else {
			if (stat(autofile, &s) != 0) {
				/* User does not want to auto-unmount */
				syslog(LOG_DEBUG, "pam_ecryptfs: Skipping automatic eCryptfs unmount");
				exit(0);
			}
			clearenv();
			if (setgroups(1, &pwd->pw_gid) < 0 || setgid(pwd->pw_gid) < 0)
				return -1;
			/* run umount.ecryptfs_private as the user */
			if (setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid) < 0)
				return -1;
			execl("/sbin/umount.ecryptfs_private",
 			      "umount.ecryptfs_private", NULL);
			exit(1);
		}
		exit(1);
	} else {
		waitpid(pid, &rc, 0);
	}
out:
	return 0;
}

static int mount_private_dir(pam_handle_t *pamh)
{
	return private_dir(pamh, 1);
}

static int umount_private_dir(pam_handle_t *pamh)
{
	return private_dir(pamh, 0);
}

PAM_EXTERN int
pam_sm_open_session(pam_handle_t *pamh, int flags,
		    int argc, const char *argv[])
{
	mount_private_dir(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int
pam_sm_close_session(pam_handle_t *pamh, int flags,
		     int argc, const char *argv[])
{
	umount_private_dir(pamh);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
                                int argc, const char **argv)
{
	uid_t uid = 0, oeuid = 0;
	long ngroups_max = sysconf(_SC_NGROUPS_MAX);
	gid_t gid = 0, oegid = 0, groups[ngroups_max+1];
	int ngids = 0;
	char *homedir = NULL;
	const char *username;
	char *old_passphrase = NULL;
	char *new_passphrase = NULL;
	char *wrapped_pw_filename;
	char *name = NULL;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	pid_t child_pid, tmp_pid;
	int rc = PAM_SUCCESS;

	rc = pam_get_user(pamh, &username, NULL);
	if (rc == PAM_SUCCESS) {
		struct passwd *pwd;

		pwd = getpwnam(username);
		if (pwd) {
			uid = pwd->pw_uid;
			gid = pwd->pw_gid;
			homedir = pwd->pw_dir;
			name = pwd->pw_name;
		}
	} else {
		syslog(LOG_ERR, "pam_ecryptfs: Error getting passwd info for user [%s]; rc = [%d]\n", username, rc);
		goto out;
	}

	if ((oeuid = geteuid()) < 0 || (oegid = getegid()) < 0 ||
	    (ngids = getgroups(sizeof(groups)/sizeof(gid_t), groups)) < 0) {
		syslog(LOG_ERR, "pam_ecryptfs: geteuid error");
		goto outnouid;
	}

	if (setegid(gid) < 0 || setgroups(1, &gid) < 0 || seteuid(uid) < 0) {
		syslog(LOG_ERR, "pam_ecryptfs: seteuid error");
		goto out;
	}

	if ((rc = pam_get_item(pamh, PAM_OLDAUTHTOK,
			       (const void **)&old_passphrase))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_ecryptfs: Error retrieving old passphrase; rc = [%d]\n", rc);
		goto out;
	}
	/* On the first pass, do nothing except check that we have a password */
	if ((flags & PAM_PRELIM_CHECK)) {
		if (!old_passphrase)
		{
			syslog(LOG_WARNING, "pam_ecryptfs: PAM passphrase change module retrieved a NULL passphrase; nothing to do\n");
			rc = PAM_AUTHTOK_RECOVER_ERR;
		}
		goto out;
	}
	if ((rc = pam_get_item(pamh, PAM_AUTHTOK,
			       (const void **)&new_passphrase))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, "pam_ecryptfs: Error retrieving new passphrase; rc = [%d]\n", rc);
		goto out;
	}
	if ((rc = asprintf(&wrapped_pw_filename, "%s/.ecryptfs/%s", homedir,
			   ECRYPTFS_DEFAULT_WRAPPED_PASSPHRASE_FILENAME))
	    == -1) {
		syslog(LOG_ERR, "pam_ecryptfs: Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = ecryptfs_read_salt_hex_from_rc(salt_hex))) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else {
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	}
	if (wrap_passphrase_if_necessary(username, uid, wrapped_pw_filename, new_passphrase, salt) == 0) {
		syslog(LOG_DEBUG, "pam_ecryptfs: Passphrase file wrapped");
	} else {
		goto out;
	}

	if (!old_passphrase || !new_passphrase || *new_passphrase == '\0') {
		syslog(LOG_WARNING, "pam_ecryptfs: PAM passphrase change module retrieved at least one NULL passphrase; nothing to do\n");
		rc = PAM_AUTHTOK_RECOVER_ERR;
		goto out;
	}
	rc = PAM_SUCCESS;
	if ((child_pid = fork()) == 0) {
		char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1];

		/* temp regain uid 0 to drop privs */
		seteuid(oeuid);
		/* setgroups() already called */
		if (setgid(gid) < 0 || setuid(uid) < 0)
			goto out_child;

		if ((rc = ecryptfs_unwrap_passphrase(passphrase,
						     wrapped_pw_filename,
						     old_passphrase, salt))) {
			syslog(LOG_ERR, "pam_ecryptfs: Error attempting to unwrap passphrase; rc = [%d]\n", rc);
			goto out_child;
		}
		if ((rc = ecryptfs_wrap_passphrase(wrapped_pw_filename,
						   new_passphrase, salt,
						   passphrase))) {
			syslog(LOG_ERR, "pam_ecryptfs: Error attempting to wrap passphrase; rc = [%d]", rc);
			goto out_child;
		}
out_child:
		exit(0);
	}
	if ((tmp_pid = waitpid(child_pid, NULL, 0)) == -1)
		syslog(LOG_WARNING, "pam_ecryptfs: waitpid() returned with error condition\n");
	free(wrapped_pw_filename);
out:

	seteuid(oeuid);
	setegid(oegid);
	setgroups(ngids, groups);

outnouid:
	return rc;
}
