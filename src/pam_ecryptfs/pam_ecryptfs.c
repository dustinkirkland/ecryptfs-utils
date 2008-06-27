/**
 * pam_ecryptfs.c: PAM module that sends the user's authentication
 * tokens into the kernel keyring.
 *
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
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

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdarg.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>
#include <pwd.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <security/pam_modules.h>
#include "config.h"
#include "../include/ecryptfs.h"

#define PRIVATE_DIR "Private"

static void error(const char *msg)
{
	syslog(LOG_ERR, "errno = [%i]; strerror = [%s]\n", errno,
	       strerror(errno));
	switch (errno) {
	case ENOKEY:
		syslog(LOG_ERR, "%s: Requested key not available\n", msg);
		return;

	case EKEYEXPIRED:
		syslog(LOG_ERR, "%s: Key has expired\n", msg);
		return;

	case EKEYREVOKED:
		syslog(LOG_ERR, "%s: Key has been revoked\n", msg);
		return;

	case EKEYREJECTED:
		syslog(LOG_ERR, "%s: Key was rejected by service\n", msg);
		return;
	default:
		syslog(LOG_ERR, "%s: Unknown key error\n", msg);
		return;
	}
}

PAM_EXTERN int pam_sm_authenticate(pam_handle_t *pamh, int flags, int argc,
				   const char **argv)
{
	uid_t uid = 0;
	char *homedir = NULL;
	uid_t saved_uid = 0;
	const char *username;
	char *passphrase = NULL;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	char *auth_tok_sig;
	pid_t child_pid, tmp_pid;
	long rc;

	syslog(LOG_INFO, "%s: Called\n", __FUNCTION__);
	rc = pam_get_user(pamh, &username, NULL);
	if (rc == PAM_SUCCESS) {
		struct passwd *pwd;

		syslog(LOG_INFO, "%s: username = [%s]\n", __FUNCTION__,
		       username);
		pwd = getpwnam(username);
		if (pwd) {
			uid = pwd->pw_uid;
			homedir = pwd->pw_dir;
		}
	} else {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
		       "rc = [%ld]\n", username, rc);
		goto out;
	}
	saved_uid = geteuid();
	seteuid(uid);
	rc = pam_get_item(pamh, PAM_AUTHTOK, (const void **)&passphrase);
	seteuid(saved_uid);
	if (rc != PAM_SUCCESS) {
		syslog(LOG_ERR, "Error retrieving passphrase; rc = [%d]\n",
		       rc);
		goto out;
	}
	auth_tok_sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!auth_tok_sig) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Out of memory\n");
		goto out;
	}
	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		syslog(LOG_WARNING, "Unable to read salt value from user's "
		       ".ecryptfsrc file; using default\n");
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((child_pid = fork()) == 0) {
		setuid(uid);
		if (passphrase == NULL) {
			syslog(LOG_ERR, "NULL passphrase; aborting\n");
			rc = -EINVAL;
			goto out_child;
		}
		if ((rc = ecryptfs_validate_keyring())) {
			syslog(LOG_WARNING,
			       "Cannot validate keyring integrity\n");
		}
		rc = 0;
		if ((argc == 1)
		    && (memcmp(argv[0], "unwrap\0", 7) == 0)) {
			char *wrapped_pw_filename;
			
			rc = asprintf(
				&wrapped_pw_filename, "%s/.ecryptfs/%s",
				homedir,
				ECRYPTFS_DEFAULT_WRAPPED_PASSPHRASE_FILENAME);
			if (rc == -1) {
				syslog(LOG_ERR, "Unable to allocate memory\n");
				rc = -ENOMEM;
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
			syslog(LOG_WARNING, "There is already a key in the "
			       "user session keyring for the given "
			       "passphrase.\n");
			rc = 0;
		}
		if (rc) {
			syslog(LOG_ERR, "Error adding passphrase key token to "
			       "user session keyring; rc = [%d]\n", rc);
			goto out_child;
		}
		if (fork() == 0) {
			if ((rc = ecryptfs_set_zombie_session_placeholder())) {
				syslog(LOG_ERR, "Error attempting to create "
				       "and register zombie process; "
				       "rc = [%d]\n", rc);
			}
		}
out_child:
		free(auth_tok_sig);
		exit(0);
	}
	tmp_pid = waitpid(child_pid, NULL, 0);
	if (tmp_pid == -1)
		syslog(LOG_WARNING,
		       "waitpid() returned with error condition\n");
out:
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_setcred(pam_handle_t *pamh, int flags, int argc,
			      const char **argv)
{
	return PAM_SUCCESS;
}

struct passwd *fetch_pwd(pam_handle_t *pamh)
{
	long rc;
	char *username = NULL;
	struct passwd *pwd = NULL;
	rc = pam_get_user(pamh, &username, NULL);
	if (rc != PAM_SUCCESS || username == NULL) {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
				"rc = [%ld]\n", username, rc);
		return NULL;
	}
	pwd = getpwnam(username);
	if (pwd == NULL) {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
				"rc = [%ld]\n", username, rc);
		return NULL;
	}
	return pwd;
}

int private_dir(pam_handle_t *pamh, int mount)
{
	int rc;
	struct passwd *pwd = NULL;
	char *sigfile = NULL;
	struct stat s;
	pid_t pid;
	struct utmp *u;
	int count = 0;

	if ((pwd = fetch_pwd(pamh)) == NULL) {
		/* fetch_pwd() logged a message */
		return 1;
	}
        if (
	    (asprintf(&sigfile, "%s/.ecryptfs/%s.sig", pwd->pw_dir, 
	     PRIVATE_DIR) < 0) || sigfile == NULL) {
		syslog(LOG_ERR, "Error allocating memory for sigfile name");
		return 1;
        }
	if (stat(sigfile, &s) != 0) {
		syslog(LOG_ERR, "Error allocating memory for sigfile name");
		return 1;
	}
	if (!S_ISREG(s.st_mode)) {
		/* No sigfile, no need to mount private dir */
		goto out;
	}
	if ((pid = fork()) < 0) {
		syslog(LOG_ERR, "Error setting up private mount");
		return 1;
	} 
	if (pid == 0) {
		if (mount == 1) {
			/* run mount.ecryptfs_private as the user */
			setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid);
			execl("/sbin/mount.ecryptfs_private", 
			      "mount.ecryptfs_private", NULL);
		} else {
			/* run umount.ecryptfs_private as the user */
			setresuid(pwd->pw_uid, pwd->pw_uid, pwd->pw_uid);
			execl("/sbin/umount.ecryptfs_private", 
 			      "umount.ecryptfs_private", NULL);
		}
		return 1;
	} else {
		wait(&rc);
		syslog(LOG_INFO, 
		       "Mount of private directory return code [%d]", rc);
		goto out;
	}
out:
	return 0;
}

int mount_private_dir(pamh) {
	return private_dir(pamh, 1);
}

int umount_private_dir(pamh) {
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
	umount_private_dir(pamh, 0);
	return PAM_SUCCESS;
}

PAM_EXTERN int pam_sm_chauthtok(pam_handle_t * pamh, int flags,
                                int argc, const char **argv)
{
	uid_t uid = 0;
	char *homedir = NULL;
	uid_t saved_uid = 0;
	const char *username;
	char *old_passphrase = NULL;
	char *new_passphrase = NULL;
	char *wrapped_pw_filename;
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
			homedir = pwd->pw_dir;
		}
	} else {
		syslog(LOG_ERR, "Error getting passwd info for user [%s]; "
		       "rc = [%ld]\n", username, rc);
		goto out;
	}
	saved_uid = geteuid();
	seteuid(uid);
	if ((rc = pam_get_item(pamh, PAM_OLDAUTHTOK,
			       (const void **)&old_passphrase))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, "Error retrieving old passphrase; rc = [%d]\n",
		       rc);
		seteuid(saved_uid);
		goto out;
	}
	if ((rc = pam_get_item(pamh, PAM_AUTHTOK,
			       (const void **)&new_passphrase))
	    != PAM_SUCCESS) {
		syslog(LOG_ERR, "Error retrieving new passphrase; rc = [%d]\n",
		       rc);
		seteuid(saved_uid);
		goto out;
	}
	seteuid(saved_uid);
	if (!old_passphrase || !new_passphrase) {
		syslog(LOG_WARNING, "eCryptfs PAM passphrase change module "
		       "retrieved at least one NULL passphrase; nothing to "
		       "do\n");
		goto out;
	}
	if ((rc = asprintf(&wrapped_pw_filename, "%s/.ecryptfs/%s", homedir,
			   ECRYPTFS_DEFAULT_WRAPPED_PASSPHRASE_FILENAME))
	    == -1) {
		syslog(LOG_ERR, "Unable to allocate memory\n");
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = ecryptfs_read_salt_hex_from_rc(salt_hex))) {
		syslog(LOG_WARNING, "Unable to read salt value from user's "
		       ".ecryptfsrc file; using default\n");
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	rc = PAM_SUCCESS;
	if ((child_pid = fork()) == 0) {
		char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1];

		setuid(uid);
		if ((rc = ecryptfs_unwrap_passphrase(passphrase,
						     wrapped_pw_filename,
						     old_passphrase, salt))) {
			syslog(LOG_ERR, "Error attempting to unwrap "
			       "passphrase; rc = [%d]\n", rc);
			goto out_child;
		}
		if ((rc = ecryptfs_wrap_passphrase(wrapped_pw_filename,
						   new_passphrase, salt,
						   passphrase))) {
			syslog(LOG_ERR, "Error attempting to wrap passphrase; "
			       "rc = [%d]", rc);
			goto out_child;
		}
out_child:
		exit(0);
	}
	if ((tmp_pid = waitpid(child_pid, NULL, 0)) == -1)
		syslog(LOG_WARNING,
		       "waitpid() returned with error condition\n");
	free(wrapped_pw_filename);
out:
	return rc;
}
