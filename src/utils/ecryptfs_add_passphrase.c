/**
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
 *            Dustin Kirkland <kirkland@canonical.com>
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
#include <string.h>
#include <ecryptfs.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "\n"
	       "ecryptfs-add-passphrase [passphrase]\n"
	       "or\n"
	       "printf \"passphrase\" | ecryptfs-add-passphrase -\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1];
	char auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;
	char *p;

	if (argc != 2) {
		usage();
		goto out;
	}
	if (strlen(argv[1]) == 1 && strncmp(argv[1], "-", 1) == 0) {
		if (fgets(passphrase,
			  ECRYPTFS_MAX_PASSWORD_LENGTH, stdin) == NULL) {
			usage();
			goto out;
		}
		p = strrchr(passphrase, '\n');
		if (p) *p = '\0';
	} else {
		memcpy(passphrase, argv[1], ECRYPTFS_MAX_PASSWORD_LENGTH);
		passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH] = '\0';
	}
	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		fprintf(stderr, "%s\n", ECRYPTFS_WARN_DEFAULT_SALT);
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig_hex,
							 passphrase, salt))) {
		printf("Error attempting to insert passphrase "
		       "into the user session keyring; rc = [%d]. "
		       "Check the system log for more information from "
		       "libecryptfs.\n", rc);
		rc = 1;
		goto out;
	}
	auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	printf("Inserted auth tok with sig [%s] into the user session "
	       "keyring\n", auth_tok_sig_hex);
out:
	return rc;
}
