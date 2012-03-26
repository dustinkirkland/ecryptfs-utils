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

#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>
#include <fcntl.h>

#define TEST_PASSED	(0)
#define TEST_FAILED	(1)
#define TEST_ERROR	(2)

/*
 *  https://bugs.launchpad.net/ubuntu/+source/linux/+bug/524919
 *
 *  test that readlink() and lstat() size of a symlink are the same length
 */
int main(int argc, char **argv)
{
	char link[PATH_MAX];
	char buf[PATH_MAX];
	struct stat statbuf;
	int rc = TEST_PASSED;
	int fd;
	ssize_t n;

	if (argc < 2) {
		fprintf(stderr, "Usage: filename\n");
		exit(TEST_ERROR);
	}

	if ((fd = open(argv[1], O_CREAT | O_RDWR, S_IRUSR | S_IWUSR)) < 0) {
		fprintf(stderr, "cannot create %s : %s\n", argv[1],
			strerror(errno));
		exit(TEST_ERROR);
	}

	if (close(fd) < 0) {
		fprintf(stderr, "close failed %s: %s\n", argv[1],
			strerror(errno));
		rc = TEST_ERROR;
		goto tidy_file;
	}

	snprintf(link, sizeof(link), "%s-symlink", argv[1]);
	if (symlink(argv[1], link) < 0) {
		fprintf(stderr, "symlink failed %s: %s\n", argv[1],
			strerror(errno));
		rc = TEST_ERROR;
		goto tidy_file;
	}

	n = readlink(link, buf, sizeof(buf));
	if (n < 0) {
		fprintf(stderr, "readlink failed %s: %s\n", argv[1],
			strerror(errno));
		rc = TEST_ERROR;
		goto tidy_symlink;
	}
	if (lstat(link, &statbuf) < 0) {
		fprintf(stderr, "lstat failed %s: %s\n", argv[1],
			strerror(errno));
		rc = TEST_ERROR;
		goto tidy_symlink;
	}

	/* Should be the same size */
	if (statbuf.st_size != n)
		rc = TEST_FAILED;

tidy_symlink:
	unlink(link);
tidy_file:
	unlink(argv[1]);

	exit(rc);
}
