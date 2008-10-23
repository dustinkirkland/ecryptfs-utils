/**
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
#include <ecryptfs.h>
#include <string.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs_wrap_passphrase [file] [passphrase to wrap] "
	       "[wrapping passphrase]\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char *file;
	char *passphrase;
	char *wrapping_passphrase;
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;
	char *p;

	if (argc == 3 && strlen(argv[2]) == 1 && strncmp(argv[2], "-", 1) == 0) {
		if ((passphrase = (char *)malloc(ECRYPTFS_MAX_PASSWORD_LENGTH+1)) == NULL) {
			perror("malloc");
			goto out;
		}
		if ((wrapping_passphrase = (char *)malloc(ECRYPTFS_MAX_PASSWORD_LENGTH+1)) == NULL) {
			perror("malloc");
			goto out;
		}
		if (fgets(passphrase, ECRYPTFS_MAX_PASSWORD_LENGTH, stdin) == NULL) {
			usage();
			goto out;
		}
		p = strrchr(passphrase, '\n');
		if (p) *p = '\0';
		if (fgets(wrapping_passphrase, ECRYPTFS_MAX_PASSWORD_LENGTH, stdin) == NULL) {
			usage();
			goto out;
		}
		p = strrchr(wrapping_passphrase, '\n');
		if (p) *p = '\0';
	} else if (argc == 4) {
		passphrase = argv[2];
		wrapping_passphrase = argv[3];
	} else {
		usage();
		goto out;
	}
	file = argv[1];
	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		printf("Unable to read salt value from user's "
		       ".ecryptfsrc file; using default\n");
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_wrap_passphrase(file, wrapping_passphrase, salt,
					   passphrase))) {
		printf("Error attempting to wrap passphrase; rc = [%d]. "
		       "Check the system log for more information from "
		       "libecryptfs.\n", rc);
		rc = 1;
		goto out;
	}
out:
	return rc;
}
