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
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <limits.h>

#define TEST_PASSED	(0)
#define TEST_FAILED	(1)
#define TEST_ERROR	(2)

#define BUFF_SIZE	(4096)

/*
 *  https://bugs.launchpad.net/ubuntu/+source/linux/+bug/719691
 *
 *  read() on a directory should return EISDIR, but bug LP: #719691
 *  ecryptfs returns EINVAL in contradiction to SUSv2.
 */
int main(int argc, char **argv)
{
	int fd;
	int ret;
	char path[PATH_MAX];
	char buff[BUFF_SIZE];

	if (argc < 2) {
		fprintf(stderr, "Usage: path\n");
		exit(TEST_ERROR);
	}
	snprintf(path, sizeof(path), "%s/.", argv[1]);

	if ((fd = open(path, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot open ./. : %s\n", strerror(errno));
		exit(TEST_ERROR);
	}

	ret = read(fd, buff, sizeof(buff));
	if (ret >= 0) {
		/* Should not be abled to read a directory */
		fprintf(stderr, "read() on a directory should fail, but did not\n");
		close(fd);
		exit(TEST_FAILED);
	}

	if (errno != EISDIR) {
		fprintf(stderr, "read() on a directory should set errno to EISDIR, "
			"instead got: %d - %s\n", errno, strerror(errno));
		close(fd);
		exit(TEST_FAILED);
	}

	close(fd);
	exit(TEST_PASSED);
}
