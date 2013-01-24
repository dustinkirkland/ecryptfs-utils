/*
 * Author: Colin King <colin.king@canonical.com>
 *
 * Copyright (C) 2013 Canonical, Ltd.
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/xattr.h>

static const char *names[]  = {
	"user.test1",
	"user.test2",
	"user.test3",
	NULL
};

static const char *values[] = {
	"test value #1",
	"test value #2",
	"test value #3",
	NULL
};

int main(int argc, char **argv)
{
	ssize_t len, names_len = 0;
	int i, rc;
	char buffer[1024];
	char *ptr = buffer;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s file\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	for (i = 0; names[i]; i++) {
		if (setxattr(argv[1], names[i], values[i], strlen(values[i]), 0) < 0)
			exit(EXIT_FAILURE);
		names_len += 1 + strlen(names[i]);
	}

	/*
	 *  Sanity check that listxattr returns correct length
	 */
	len = listxattr(argv[1], NULL, 0);
	if (len != names_len)
		exit(EXIT_FAILURE);

	len = listxattr(argv[1], buffer, sizeof(buffer));
	if (len < 0)
		exit(EXIT_FAILURE);

	/*  
	 *  Check listxattr names match what has been just set
	 */
	for (i = 0; names[i]; i++) {
		if (strcmp(names[i], ptr))
			exit(EXIT_FAILURE);
		ptr += strlen(ptr) + 1;
	}

	/*
	 *  Check contents of xattr
	 */
	for (i = 0; names[i]; i++) {
		len = getxattr(argv[1], names[i], buffer, sizeof(buffer));
		if (len < 0)
			exit(EXIT_FAILURE);
		buffer[len] = '\0';

		if (strcmp(values[i], buffer))
			exit(EXIT_FAILURE);
	}
	
	/*
	 *  Remove xattr
	 */
	for (i = 0; names[i]; i++) {
		rc = removexattr(argv[1], names[i]);
		if (rc < 0)
			exit(EXIT_FAILURE);
	}

	/*
	 *  ..and there should be no xattrs left
	 */
	len = listxattr(argv[1], NULL, 0);
	if (len != 0)
		exit(EXIT_FAILURE);
		
	exit(EXIT_SUCCESS);
}
