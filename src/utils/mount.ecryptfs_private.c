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


#include <sys/mount.h>
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

/* Perhaps a future version of this program will allow these to be configurable
 * by the system administrator (or user?) at run time.  For now, these are set
 * to reasonable values to reduce the burden of input validation.
 */
#define KEY_BYTES 16
#define KEY_CIPHER "aes"
#define PRIVATE_DIR "Private"
#define FSTYPE "ecryptfs"


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


char *fetch_sig(char *pw_dir) {
/* Read ecryptfs signature from file and validate 
 * Return signature as a string, or NULL on failure
 */
	char *sig_file, c;
	FILE *fh;
	char *sig;
	int i;
	/* Construct sig file name */
	if (
	    asprintf(&sig_file, "%s/.ecryptfs/%s.sig", pw_dir, PRIVATE_DIR) < 0
	   ) {
		perror("asprintf");
		return NULL;
	}
	fh = fopen(sig_file, "r");
	if (fh == NULL) {
		syslog(LOG_ERR, "%s: Error opening [%s] for read\n",
		       __FUNCTION__, sig_file);
		perror("fopen");
		return NULL;
	}
	if ((sig = (char *)malloc(KEY_BYTES*sizeof(char)+1)) == NULL) {
		perror("malloc");
		return NULL;
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
		fputs("Invalid hex signature length\n", stderr);
		return NULL;
	}
	sig[KEY_BYTES] = '\0';
	/* Validate that signature is in the current keyring,
	 * compile with -lkeyutils
	 */
	if ((int)keyctl_search(KEY_SPEC_USER_KEYRING, "user", sig, 0) == -1) {
		perror("keyctl_search");
		return NULL;
	}
	return sig;
}


int check_ownerships(int uid, char *dev, char *mnt) {
/* Check ownership of device and mount point.
 * Return 0 if everything is in order, 1 on error.
 */
	struct stat s;
	if (stat(dev, &s) != 0) {
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
	if (stat(mnt, &s) != 0) {
		fputs("Cannot examine mount directory\n", stderr);
		return 1;
	}
	if (s.st_uid != uid) {
		fputs("You do not own that mount directory\n", stderr);
		return 1;
	}
	return 0;
}

int is_mounted(char *dev, char *mnt, char *sig, int mounting) {
/* Check if a device or mount point is mounted.
 * Return 1 if a filesystem in mtab matches dev && mnt && sig.
 * Return 0 otherwise.
 */
	FILE *fh;
	struct mntent *m;
	char *opt;
	int mounted;
	if (asprintf(&opt, "ecryptfs_sig=%s", sig) < 0) {
		perror("asprintf");
		return 1;
	}
	if (mounting == 1) {
		/* If we're mounting, we want to broadly search mounts that
		 * might exist in /proc/mounts but not /etc/mtab; and we
		 * are going to disregard the ecryptfs_sig option
		 */
		fh = setmntent("/proc/mounts", "r");
	} else {
		/* If we're unmounting, we need to check the ecryptfs_sig
		 * option which only shows up in /etc/mtab
		 */
		fh = setmntent("/etc/mtab", "r");
	}
	if (fh == NULL) {
		perror("setmntent");
		return 1;
	}
	mounted = 0;
	while ((m = getmntent(fh)) != NULL) {
		if (mounting == 1) {
			/* If mounting, return "already mounted" if EITHER the 
 			 * dev or the mnt dir shows up in mtab/mounts;
 			 * regardless of the signature of such mounts;
 			 */
			if (
			    strcmp(m->mnt_fsname, dev) == 0 ||
			    strcmp(m->mnt_dir, mnt) == 0
			) {
				mounted = 1;
			}
		} else {
			/* Otherwise, we're unmounting, and we need to be
			 * very conservative in finding a perfect match
			 * to unmount.  The device, mountpoint, and signature
			 * must *all* match perfectly.
			 */
			if (
			    strcmp(m->mnt_fsname, dev) == 0 &&
			    strcmp(m->mnt_dir, mnt) == 0 &&
			    hasmntopt(m, opt) != NULL
			) {
				mounted = 1;
			}
		}
	}
	endmntent(fh);
	return mounted;
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
	int uid, rc, mounting;
	struct passwd *pwd;
	char *dev, *mnt, *opt;
	char *sig;

	uid = getuid();
	if ((pwd = getpwuid(uid)) == NULL) {
		perror("getpwuid");
		return 1;
	}

	/* Non-privileged effective uid is sufficient for all but the code
 	 * that mounts, unmounts, and updates /etc/mtab.
	 * Run at a lower privilege until we need it.
	 */
	if (seteuid(uid)<0 || geteuid()!=uid) {
		perror("setuid");
		return 1;
	}

	if (check_username(pwd->pw_name) != 0) {
		/* Must protect against a crafted user=john,suid from entering
		 * filesystem options
		 */
		return 1;
	}

	/* Determine if mounting or unmounting by looking at the invocation */
	if (strstr(argv[0], "umount") == NULL) {
		mounting = 1;
	} else {
		mounting = 0;
	}

	/* Fetch signature from file */
	if ((sig = fetch_sig(pwd->pw_dir)) == NULL) {
		return 1;
	}

	/* Construct device, mount point, and mount options */
	if (
	    (asprintf(&dev, "%s/.%s", pwd->pw_dir, PRIVATE_DIR) < 0) || 
	    dev == NULL) {
		perror("asprintf (dev)");
		return 1;
	}
	if (
	    (asprintf(&mnt, "%s/%s", pwd->pw_dir, PRIVATE_DIR) < 0) ||
	    mnt == NULL) {
		perror("asprintf (mnt)");
		return 1;
	}
	if ((asprintf(&opt, 
	 "rw,ecryptfs_sig=%s,ecryptfs_cipher=%s,ecryptfs_key_bytes=%d,user=%s",
	 sig, KEY_CIPHER, KEY_BYTES, pwd->pw_name) < 0) ||
	 opt == NULL) {
		perror("asprintf (opt)");
		return 1;
	}

	/* Check ownership of dev and mnt */
	if (check_ownerships(uid, dev, mnt) != 0) {
		return 1;
	}

	if (mounting == 1) {
		/* Mounting, so exit if already mounted */
		if (is_mounted(dev, mnt, sig, mounting) == 1) {
			return 1;
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
				return 1;
			}
		} else {
			perror("mount");
			return 1;
		}
	} else {
		/* Unmounting, so exit if not mounted */
		if (is_mounted(dev, mnt, sig, mounting) == 0) {
			return 1;
		}
		/* The key is not needed for unmounting, so we set res=0.
		 * Perform umount by calling umount utility.  This execl will
 		 * update mtab for us, and replace the current process.
		 * Do not use the umount.ecryptfs helper (-i).
 		 */
		setresuid(0,0,0);
		execl("/bin/umount", "umount", "-i", mnt, NULL);
		perror("execl unmount failed");
		return 1;
	}
	return 0;
}
