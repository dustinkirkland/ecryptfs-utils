/**
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

#include <stdio.h>
#include <ecryptfs.h>
#include <string.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs-rewrap-passphrase [file]\n"
	       "or\n"
	       "printf \"%%s\\n%%s\" \"old wrapping passphrase\" "
	       "\"new wrapping passphrase\" "
	       "| ecryptfs-rewrap-passphrase [file] -\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char *file;
	char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1];
	char *old_wrapping_passphrase;
	char *new_wrapping_passphrase;
	char *new_wrapping_passphrase2;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;

	if (argc == 2) {
		/* interactive mode */
		old_wrapping_passphrase =
			ecryptfs_get_passphrase("Old wrapping passphrase");
		new_wrapping_passphrase =
			ecryptfs_get_passphrase("New wrapping passphrase");
		new_wrapping_passphrase2 =
			ecryptfs_get_passphrase("New wrapping passphrase (again)");
		if (
		    strlen(new_wrapping_passphrase) != strlen(new_wrapping_passphrase2) ||
		    strncmp(new_wrapping_passphrase, new_wrapping_passphrase2, strlen(new_wrapping_passphrase))!=0
		   ) {
			fprintf(stderr, "New wrapping passphrases do not match\n");
			rc = 1;
			goto out;
		}
	} else if (argc == 3
		   && strlen(argv[2]) == 1 && strncmp(argv[2], "-", 1) == 0) {
		/* stdin mode */
		old_wrapping_passphrase = ecryptfs_get_passphrase(NULL);
		new_wrapping_passphrase = ecryptfs_get_passphrase(NULL);
	} else if (argc == 4) {
		/* argument mode */
		old_wrapping_passphrase = argv[2];
		new_wrapping_passphrase = argv[3];
	} else {
		usage();
		goto out;
	}
	if (old_wrapping_passphrase==NULL || new_wrapping_passphrase==NULL ||
	    strlen(old_wrapping_passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH ||
	    strlen(new_wrapping_passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
		usage();
		goto out;
	}

	file = argv[1];
	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_unwrap_passphrase(passphrase, file,
					     old_wrapping_passphrase, salt))) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_UNWRAP, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	}
	if ((rc = ecryptfs_wrap_passphrase(file, new_wrapping_passphrase, salt,
					   passphrase))) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_WRAP, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	}
out:
	return rc;
}
