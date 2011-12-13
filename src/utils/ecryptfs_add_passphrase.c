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
#include <string.h>
#include <ecryptfs.h>
#include "config.h"

void usage(void)
{
	printf("Usage:\n"
	       "ecryptfs-add-passphrase [--fnek]\n"
	       "or\n"
	       "printf \"%%s\" \"passphrase\" | ecryptfs-add-passphrase"
	       " [--fnek] -\n"
	       "\n");
}

int main(int argc, char *argv[])
{
	char *passphrase;
	char auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
	char salt[ECRYPTFS_SALT_SIZE];
	char salt_hex[ECRYPTFS_SALT_SIZE_HEX];
	int rc = 0;
	int fnek = 0;
	uint32_t version;

	if (argc == 1) {
		/* interactive mode */
		passphrase = ecryptfs_get_passphrase("Passphrase");
	} else if (argc == 2 &&
		   strlen(argv[1]) == 6 && strncmp(argv[1], "--fnek", 6) == 0) {
		/* interactive mode, plus fnek */
		passphrase = ecryptfs_get_passphrase("Passphrase");
		fnek = 1;
	} else if (argc == 2 &&
		   strlen(argv[1]) == 1 && strncmp(argv[1], "-", 1) == 0) {
		/* stdin mode */
		passphrase = ecryptfs_get_passphrase(NULL);
	} else if (argc == 3 &&
		/* stdin mode, plus fnek */
		   (strlen(argv[1])==6 && strncmp(argv[1], "--fnek", 6)==0) &&
		   (strlen(argv[2])==1 && strncmp(argv[2], "-", 1)==0)) {
		passphrase = ecryptfs_get_passphrase(NULL);
		fnek = 1;
	} else {
		usage();
		goto out;
	}
	if (passphrase == NULL ||
	    strlen(passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
		usage();
		rc = 1;
		goto out;
	}
	if (fnek == 1) {
		rc = ecryptfs_get_version(&version);
		if (rc!=0 || !ecryptfs_supports_filename_encryption(version)) { 
			fprintf(stderr, "%s\n", ECRYPTFS_ERROR_FNEK_SUPPORT);
			rc = 1;
			goto out;
		}
	}

	rc = ecryptfs_read_salt_hex_from_rc(salt_hex);
	if (rc) {
		from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	} else
		from_hex(salt, salt_hex, ECRYPTFS_SALT_SIZE);
	if ((rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig_hex,
							 passphrase,
							 salt)) < 0) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_INSERT_KEY, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	} else
		rc = 0;
	auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	printf("Inserted auth tok with sig [%s] into the user session "
	       "keyring\n", auth_tok_sig_hex);

	if (fnek == 0) {
		goto out;
	}

	/* If we make it here, filename encryption is enabled, and it has
	 * been requested that we add the fnek to the keyring too
	 */
	if ((rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig_hex,
				 passphrase,
				 ECRYPTFS_DEFAULT_SALT_FNEK_HEX)) < 0) {
		fprintf(stderr, "%s [%d]\n", ECRYPTFS_ERROR_INSERT_KEY, rc);
		fprintf(stderr, "%s\n", ECRYPTFS_INFO_CHECK_LOG);
		rc = 1;
		goto out;
	} else
		rc = 0;
	auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX] = '\0';
	printf("Inserted auth tok with sig [%s] into the user session "
	       "keyring\n", auth_tok_sig_hex);

out:
	return rc;
}
