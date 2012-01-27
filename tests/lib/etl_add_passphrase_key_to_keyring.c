/**
 * etl_add_passphrase_key_to_keyring: C bindings for libecryptfs's
 * 			ecryptfs_add_passphrase_key_to_keyring() function
 * Author: Tyler Hicks <tyhicks@canonical.com>
 *
 * Copyright (C) 2012 Canonical, Ltd.
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 2
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA
 * 02110-1301, USA
 */

#include <errno.h>
#include <stdio.h>
#include "../../src/include/ecryptfs.h"

int main(int argc, char *argv[])
{
	char auth_tok_sig_hex[ECRYPTFS_SIG_SIZE_HEX + 1];
	char salt[ECRYPTFS_SALT_SIZE + 1];
	int rc;

	if (argc != 3) {
		fprintf(stderr, "%s PASSPHRASE SALT_HEX\n", argv[0]);
		return EINVAL;
	}

	from_hex(salt, argv[2], ECRYPTFS_SALT_SIZE);
	rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig_hex, argv[1],
						    salt);
	/* If the key is already added to the keyring, 1 is returned */
	if (rc == 1)
		rc = 0;
	if (!rc)
		printf("%s\n", auth_tok_sig_hex);

	return rc;
}

