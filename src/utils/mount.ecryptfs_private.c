/*
 * This is an ecryptfs private directory mount/unmount helper program
 * for non-root users.
 *
 * Copyright (C) 2008 Canonical Ltd.
 *
 * This code was originally written by Dustin Kirkland <kirkland@ubuntu.com>.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along
 * with this program; if not, see <http://www.gnu.org/licenses/>.
 *
 * On Debian-based systems, the complete text of the GNU General Public
 * License can be found in /usr/share/common-licenses/GPL-2
 *
 */

#define _GNU_SOURCE

#include <sys/file.h>
#include <sys/mount.h>
#include <sys/param.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <keyutils.h>
#include <mntent.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <syslog.h>
#include <values.h>
#include "../include/ecryptfs.h"

/* Perhaps a future version of this program will allow these to be configurable
 * by the system administrator (or user?) at run time.  For now, these are set
 * to reasonable values to reduce the burden of input validation.
 */
#define KEY_BYTES 16
#define KEY_CIPHER "aes"
#define FSTYPE "ecryptfs"
#define TMP "/dev/shm"


int check_username(char *u) {
/* We follow the username guidelines used by the adduser program.  Quoting its
 * error message:
 *   adduser: To avoid problems, the username should consist only of
 *   letters, digits, underscores, periods, at signs and dashes, and not start
 *   with a dash (as defined by IEEE Std 1003.1-2001). For compatibility with
 *   Samba machine accounts $ is also supported at the end of the username
 */
	int i;
	char c;
	int len;
	len = strlen(u);
	if (u == NULL || len == 0) {
		fputs("Username is empty\n", stderr);
		return 1;
	}
	for (i=0; i<len; i++) {
		c = u[i];
		if ( 	!(c>='a' && c<='z') && !(c>='A' && c<='Z') &&
			!(c>='0' && c<='9') &&
			!(c=='_') && !(c=='.') && !(c=='@') &&
			!(c=='-' && i!=0) &&
			!(c=='$' && i==(len-1))
		) {
			fputs("Username has unsupported characters\n", stderr);
			return 1;
		}
	}
	return 0;
}


char *fetch_sig(char *pw_dir, int entry) {
/* Read ecryptfs signature from file and validate
 * Return signature as a string, or NULL on failure
 */
	char *sig_file, c;
	FILE *fh;
	char *sig;
	int i;
	/* Construct sig file name */
	if (
	    asprintf(&sig_file, "%s/.ecryptfs/%s.sig", pw_dir,
		     ECRYPTFS_PRIVATE_DIR) < 0
	   ) {
		perror("asprintf");
		return NULL;
	}
	fh = fopen(sig_file, "r");
	if (fh == NULL) {
		perror("fopen");
		return NULL;
	}
	if ((sig = (char *)malloc(KEY_BYTES*sizeof(char)+1)) == NULL) {
		perror("malloc");
		return NULL;
	}
	/* Move to the correct line in the file */
	if (entry == 1) {
		while ((c = fgetc(fh)) != EOF) {
			if (c == '\n') {
				break;
			}
		}
	}
	i = 0;
	/* Read KEY_BYTES characters from file */
	while ((c = fgetc(fh)) != EOF && i < KEY_BYTES) {
		if ((c>='0' && c<='9') || (c>='a' && c<='f') ||
		    (c>='A' && c<='F')) {
			sig[i] = c;
			i++;
		} else {
			fputs("Invalid hex signature\n", stderr);
			return NULL;
		}
	}
	fclose(fh);
	/* Check signature length */
	if (i != KEY_BYTES) {
		if (entry == 1 && i == 0) {
			/* This means that we have no fnek sig; tis okay */
		} else {
			fputs("Invalid hex signature length\n", stderr);
		}
		return NULL;
	}
	sig[KEY_BYTES] = '\0';
	/* Validate that signature is in the current keyring,
	 * compile with -lkeyutils
	 */
	if (keyctl_search(KEY_SPEC_USER_KEYRING, "user", sig, 0) < 0) {
		perror("keyctl_search");
		fputs("Perhaps try the interactive 'ecryptfs-mount-private'\n",
			stderr);
		return NULL;
	}
	return sig;
}

int check_ownerships(int uid, char *path) {
/* Check ownership of device and mount point.
 * Return 0 if everything is in order, 1 on error.
 */
	struct stat s;
	if (stat(path, &s) != 0) {
		fputs("Cannot examine encrypted directory\n", stderr);
		return 1;
	}
	if (!S_ISDIR(s.st_mode)) {
		fputs("Device or mountpoint is not a directory\n", stderr);
		return 1;
	}
	if (s.st_uid != uid) {
		fputs("You do not own that encrypted directory\n", stderr);
		return 1;
	}
	return 0;
}


int update_mtab(char *dev, char *mnt, char *opt) {
/* Update /etc/mtab with new mount entry.
 * Return 0 on success, 1 on failure.
 */
	FILE *fh;
	struct mntent m;
	fh = setmntent("/etc/mtab", "a");
	if (fh == NULL) {
		perror("setmntent");
		/* Unmount if mtab cannot be updated */
		umount(mnt);
		return 1;
	}
	m.mnt_fsname = dev;
	m.mnt_dir = mnt;
	m.mnt_type = FSTYPE;
	m.mnt_opts = opt;
	m.mnt_freq = 0;
	m.mnt_passno = 0;
	flockfile(fh);
	if (addmntent(fh, &m) != 0) {
		perror("addmntent");
		endmntent(fh);
		/* Unmount if mtab cannot be updated */
		umount(mnt);
		return 1;
	}
	endmntent(fh);
	return 0;
}

FILE *lock_counter(char *u, int uid) {
	char *f;
	int fd;
	FILE *fh;
	struct stat s;
	int i = 1;
	/* We expect TMP to exist, be writeable by the user,
	 * and to be cleared on boot */
	if (asprintf(&f, "%s/%s-%s-%s", TMP, FSTYPE, u, ECRYPTFS_PRIVATE_DIR) < 0) {
		perror("asprintf");
		return NULL;
	}
	/* If the counter path exists, and it's either not a regular
	 * file, or it's not owned by the current user, append iterator
	 * until we find a filename we can use.
	 */
	while (1) {
		if (stat(f, &s)==0 && (!S_ISREG(s.st_mode) || s.st_uid!=uid)) {
			free(f);
			if (asprintf(&f, "%s/%s-%s-%s-%d", TMP, FSTYPE, u,
			    ECRYPTFS_PRIVATE_DIR, i++) < 0) {
				perror("asprintf");
				return NULL;
			}
		} else {
			break;
		}
	}
	/* open file for reading and writing */
	if ((fd = open(f, O_RDWR)) < 0) {
		/* Could not open it, so try to safely create it */
		if ((fd = open(f, O_RDWR | O_CREAT | O_EXCL, 0600)) < 0) {
			perror("open");
			return NULL;
		}
	}
	flock(fd, LOCK_EX);
	fh = fdopen(fd, "r+");
	if (fh == NULL) {
		perror("fopen");
		close(fd);
		return NULL;
	}
	return fh;
}

void unlock_counter(FILE *fh) {
	if (fh != NULL) {
		/* This should remove the lock too */
		fclose(fh);
	}
}

int bump_counter(FILE *fh, int delta) {
/* Maintain a mount counter
 *   increment on delta = 1
 *   decrement on delta = -1
 *   remove the counter file on delta = 0
 *   return the updated count, negative on error
 */
	int count;
	/* Read the count from file, default to 0 */
	rewind(fh);
	if (fscanf(fh, "%d\n", &count) != 1) {
		count = 0;
	}
	/* Increment/decrement the counter */
	count += delta;
	if (count < 0) {
		/* Never set a count less than 0 */
		count = 0;
	}
	/* Write the count to file */
	rewind(fh);
	fprintf(fh, "%d\n", count);
	fflush(fh);
	return count;
}


int increment(FILE *fh) {
/* Bump counter up */
	return bump_counter(fh, 1);
}


int decrement(FILE *fh) {
/* Bump counter down */
	return bump_counter(fh, -1);
}

int zero(FILE *fh) {
/* Zero the counter file */
	return bump_counter(fh, -MAXINT+1);
}


/* This program is a setuid-executable allowing a non-privileged user to mount
 * and unmount an ecryptfs private directory.  This program is necessary to
 * keep from adding such entries to /etc/fstab.
 *
 * A single executable is created and hardlinked to two different names.
 * The mode of operation (mounting|unmounting) is determined by examining
 * the name of the executable.  "Mounting" mode is assumed, unless the
 * executable contains the string "umount".
 * Example:
 *   /sbin/mount.ecryptfs_private
 *   /sbin/umount.ecryptfs_private
 *
 * At the moment, this program:
 *  - mounts ~/.Private onto ~/Private
 *    - as an ecryptfs filesystem
 *    - using the AES cipher
 *    - with a key length of 16 bytes
 *    - and using the signature defined in ~/.ecryptfs/Private.sig
 *    - ONLY IF the user
 *      - has the signature's key in his keyring
 *      - owns both ~/.Private and ~/Private
 *      - is not already mounted
 *  - unmounts ~/.Private from ~/Private
 *    - using the signature defined in ~/.ecryptfs/Private.sig
 *    - ONLY IF the user
 *      - has the signature's key in his keyring
 *      - owns both ~/.Private and ~/Private
 *      - is currently mounted
 *
 * The only setuid operations in this program are:
 *  a) mounting
 *  b) unmounting
 *  c) updating /etc/mtab
 */
int main(int argc, char *argv[]) {
	int uid, mounting;
	int force = 0;
	int fnek = 1;
	struct passwd *pwd;
	char *dev, *mnt, *opt;
	char *sig, *sig_fnek;
	FILE *fh_counter = NULL;

	uid = getuid();
	/* Non-privileged effective uid is sufficient for all but the code
 	 * that mounts, unmounts, and updates /etc/mtab.
	 * Run at a lower privilege until we need it.
	 */
	if (seteuid(uid)<0 || geteuid()!=uid) {
		perror("setuid");
		goto fail;
	}
	if ((pwd = getpwuid(uid)) == NULL) {
		perror("getpwuid");
		goto fail;
	}

	/* Lock the counter through the rest of the program */
	fh_counter = lock_counter(pwd->pw_name, uid);
	if (fh_counter == NULL) {
		fputs("Error locking counter", stderr);
		goto fail;
	}

	if (check_username(pwd->pw_name) != 0) {
		/* Must protect against a crafted user=john,suid from entering
		 * filesystem options
		 */
		goto fail;
	}

	/* Determine if mounting or unmounting by looking at the invocation */
	if (strstr(argv[0], "umount") == NULL) {
		mounting = 1;
	} else {
		mounting = 0;
		/* Determine if unmounting is forced */
		if (argv[1] != NULL && strncmp(argv[1], "-f", 2) == 0) {
			force = 1;
		} else {
			force = 0;
		}
	}

	/* Fetch signatures from file */
	/* First line is the file content encryption key signature */
	sig = fetch_sig(pwd->pw_dir, 0);
	if (sig == NULL) {
		goto fail;
	}
	/* Second line, if present, is the filename encryption key signature */
	sig_fnek = fetch_sig(pwd->pw_dir, 1);
	if (sig_fnek == NULL) {
		fnek = 0;
	} else {
		fnek = 1;
	}

	/* Construct device, mount point, and mount options */
	if (
	    (asprintf(&dev, "%s/.%s", pwd->pw_dir, ECRYPTFS_PRIVATE_DIR) < 0) ||
	    dev == NULL) {
		perror("asprintf (dev)");
		goto fail;
	}
	mnt = ecryptfs_fetch_private_mnt(pwd->pw_dir);
	if (mnt == NULL) {
		perror("asprintf (mnt)");
		goto fail;
	}
	if (fnek == 1) {
		/* Filename encryption is on, so specific the fnek sig */
		if ((asprintf(&opt,
"ecryptfs_sig=%s,ecryptfs_fnek_sig=%s,ecryptfs_cipher=%s,ecryptfs_key_bytes=%d",
		 sig, sig_fnek, KEY_CIPHER, KEY_BYTES) < 0) ||
		 opt == NULL) {
			perror("asprintf (opt)");
			goto fail;
		}
	} else {
		/* Filename encryption is off; legacy support */
		if ((asprintf(&opt,
		 "ecryptfs_sig=%s,ecryptfs_cipher=%s,ecryptfs_key_bytes=%d",
		 sig, KEY_CIPHER, KEY_BYTES) < 0) ||
		 opt == NULL) {
			perror("asprintf (opt)");
			goto fail;
		}
	}

	/* Check ownership of mnt */
	if (check_ownerships(uid, mnt) != 0) {
		goto fail;
	}

	if (mounting == 1) {
		/* Increment mount counter, errors non-fatal */
		if (increment(fh_counter) < 0) {
			fputs("Error incrementing mount counter\n", stderr);
		}
		/* Mounting, so exit if already mounted */
		if (ecryptfs_private_is_mounted(dev, mnt, sig, mounting) == 1) {
			goto success;
		}
		/* Check ownership of dev, if mounting;
		 * note, umount only operates on mnt
		 */
		if (check_ownerships(uid, dev) != 0) {
			goto fail;
		}
		/* We must maintain our real uid as the user who called this
 		 * program in order to have access to their kernel keyring.
		 * Even though root has the power to mount, only a user with
		 * the correct key in their keyring can mount an ecryptfs
		 * directory correctly.
		 * Root does not necessarily have the user's key, so we need
		 * the real uid to be that of the user.
		 * And we need the effective uid to be root in order to mount.
		 */
		setreuid(-1, 0);
		/* Perform mount */
		if (mount(dev, mnt, FSTYPE, 0, opt) == 0) {
			if (update_mtab(dev, mnt, opt) != 0) {
				goto fail;
			}
		} else {
			perror("mount");
			/* Drop privileges since the mount did not succeed */
			if (setreuid(uid, uid) < 0) {
				perror("setreuid");
			}
			goto fail;
		}
	} else {
		/* Decrement counter, exiting if >0, and non-forced unmount */
		if (force == 1) {
			zero(fh_counter);
		} else if (decrement(fh_counter) > 0) {
			fputs("Sessions still open, not unmounting\n", stderr);
			goto fail;
		}
		/* Unmounting, so exit if not mounted */
		if (ecryptfs_private_is_mounted(dev, mnt, sig, mounting) == 0) {
			goto fail;
		}
		/* The key is not needed for unmounting, so we set res=0.
		 * Perform umount by calling umount utility.  This execl will
 		 * update mtab for us, and replace the current process.
		 * Do not use the umount.ecryptfs helper (-i).
 		 */
		setresuid(0,0,0);
		execl("/bin/umount", "umount", "-i", "-l", mnt, NULL);
		perror("execl unmount failed");
		goto fail;
	}
success:
	unlock_counter(fh_counter);
	return 0;
fail:
	unlock_counter(fh_counter);
	return 1;
}
