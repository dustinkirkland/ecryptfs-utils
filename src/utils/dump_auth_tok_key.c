/**
 * Copyright (C) 2004-2006 International Business Machines
 * Written by Michael A. Halcrow <mhalcrow@us.ibm.com>
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
#include <stddef.h>
#include <sys/types.h>
#include <keyutil.h>
#include "ecryptfs.h"

void dump_auth_tok(struct ecryptfs_auth_tok *auth_tok);

int main( int argc, char **argv )
{
	int rc;
	int key_id;
	struct ecryptfs_auth_tok auth_tok;
	if (argc != 2) {
		printf( "Usage: %s <key id>\n", argv[0]);
		exit(1);
	}
	key_id = atoi(argv[1]);
	/* Read the key */
	rc = keyctl(KEYCTL_READ, key_id, (char*)&auth_tok,
				sizeof(struct ecryptfs_auth_tok));
	if (rc < 0) {
		printf("Error reading key with id [%d]\n", key_id);
		exit(1);
	}
	printf("Successful read of key id [%d]\n",key_id);
	dump_auth_tok(&auth_tok);
	exit(0);
}
