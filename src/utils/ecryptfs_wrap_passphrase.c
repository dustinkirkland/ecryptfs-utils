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
#include <stdlib.h>
#include <ecryptfs.h>
#include <string.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs-wrap-passphrase [file]\n"
	       "or\n"
	       "printf \"%%s\\n%%s\" \"passphrase to wrap\" "
	       "\"wrapping passphrase\" "
	       "| ecryptfs-wrap-passphrase [file] -\n"
	       "\n"
	       "note: passphrase can be at most %d bytes long\n",
	       ECRYPTFS_MAX_PASSWORD_LENGTH);
}

int main(int argc, char *argv[])
{
	char *file;
	char *passphrase = NULL;
	char *wrapping_passphrase = NULL;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;

	if (argc == 2) {
		/* interactive mode */
		passphrase = ecryptfs_get_passphrase("Passphrase to wrap");
		if (passphrase)
			wrapping_passphrase =
				ecryptfs_get_passphrase("Wrapping passphrase");
	} else if (argc == 3 && strlen(argv[2]) == 1 &&
		   strncmp(argv[2], "-", 1) == 0) {
		/* stdin mode */
		passphrase = ecryptfs_get_passphrase(NULL);
		if (passphrase)
			wrapping_passphrase = ecryptfs_get_passphrase(NULL);
	} else if (argc == 4) {
		/* argument mode */
		passphrase = argv[2];
		wrapping_passphrase = argv[3];
	} else {
		usage();
		goto out;
	}
	if (passphrase == NULL || wrapping_passphrase == NULL ||
	    strlen(passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH ||
	    strlen(wrapping_passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
		usage();
		rc = 1;
		goto out;
	}
	file = argv[1];
	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_wrap_passphrase(file, wrapping_passphrase, salt,
					   passphrase))) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_WRAP, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	}
out:
	if (argc != 4) {
		free(passphrase);
		free(wrapping_passphrase);
	}
	return rc;
}
