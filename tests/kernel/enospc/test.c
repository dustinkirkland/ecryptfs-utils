/*
 * Author: Colin King <colin.king@canonical.com>
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <signal.h>
#include <limits.h>

#define TEST_PASSED	(0)
#define TEST_FAILED	(1)
#define TEST_ERROR	(2)

#define BUFF_SZ 	(65536)

int test_exercise(char *filename, ssize_t size)
{
	int fd;
	ssize_t i;
	ssize_t n;
	struct stat statbuf;
	ssize_t nbytes = size;
	int ret = TEST_FAILED;

	unsigned char buff[BUFF_SZ];

	unlink(filename);
	if ((fd = open(filename, O_RDWR | O_CREAT, 0600)) < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
		return TEST_FAILED;
	}

	memset(buff, 0, sizeof(buff));

	while (nbytes > 0) {
		int rc;
		ssize_t n = (nbytes > BUFF_SZ) ? BUFF_SZ : nbytes;

		rc = write(fd, buff, n);
		if (rc < 0) {
			if (errno == ENOSPC)
				ret = TEST_PASSED;
			break;
		}
		nbytes -= n;
	}
	/* If we got here, we didn't get ENOSPC, so we've failed */

	close(fd);
	unlink(filename);

	return ret;
}

void sighandler(int dummy)
{
	exit(TEST_ERROR);
}

int main(int argc, char **argv)
{
	ssize_t len;

	if (argc < 3) {
		fprintf(stderr, "Syntax: %s filename size_in_K\n", argv[0]);
		fprintf(stderr, "\tsize must be bigger than available space on the file system\n");
		exit(TEST_ERROR);
	}

	len = atoll(argv[2]);
	if (len < 1) {
		fprintf(stderr, "size should be > 0\n");
		exit(TEST_ERROR);
	}

	signal(SIGINT, sighandler);
	exit(test_exercise(argv[1], len * 1024));
}
