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
#include <sys/types.h>
#include <sys/stat.h>

#define TEST_ERROR	(2)

#define OFFSET		(9)

#define OPT_INC		(0x0001)
#define OPT_DEC		(0x0002)

void usage(char *name)
{
	fprintf(stderr, "Usage: [-i | -d] file\n");
}

/*
 *  https://bugs.launchpad.net/ecryptfs/+bug/509180
 *  Increment/Decrement 9th byte in lower file
 */
int main(int argc, char **argv)
{
	int fd;
	int opt, flags = 0;
	int rc = 0;
	unsigned int *ptr;
	char *file;
	unsigned char buffer[1];

	if (argc < 3) {
		usage(argv[0]);
		exit(TEST_ERROR);
	}

	while ((opt = getopt(argc, argv, "id")) != -1) {
		switch (opt) {
		case 'i':
			flags |= OPT_INC;
			break;
		case 'd':
			flags |= OPT_DEC;
			break;
		default:
			usage(argv[0]);
			exit(TEST_ERROR);
		}
	}

	if ((flags == 0) || (flags == (OPT_INC | OPT_DEC))) {
		fprintf(stderr, "Need to specify -i or -d\n");
		exit(TEST_ERROR);
	}

	file = argv[optind];

	if ((fd = open(file, O_RDWR, 0700)) < 0) {
		fprintf(stderr, "Cannot open %s : %s\n", file, strerror(errno));
		exit(TEST_ERROR);
	}

	if ((lseek(fd, (off_t)OFFSET, SEEK_SET)) < 0) {
		fprintf(stderr, "Cannot lseek to offset %d in %s : %s\n",
			OFFSET, file, strerror(errno));
		rc = TEST_ERROR;
		goto tidy;
	}

	if (read(fd, buffer, sizeof(buffer)) != sizeof(buffer)) {
		fprintf(stderr, "Failed to read\n");
		rc = TEST_ERROR;
		goto tidy;
	}

	if (flags & OPT_INC)
		buffer[0]++;

	if (flags & OPT_DEC)
		buffer[0]--;

	if ((lseek(fd, (off_t)OFFSET, SEEK_SET)) < 0) {
		fprintf(stderr, "Cannot lseek to offset %d in %s : %s\n",
			OFFSET, file, strerror(errno));
		rc = TEST_ERROR;
		goto tidy;
	}

	if (write(fd, buffer, sizeof(buffer)) != sizeof(buffer)) {
		fprintf(stderr, "Failed to write\n");
		rc = TEST_ERROR;
	}

tidy:
	if (close(fd) < 0) {
		fprintf(stderr, "Close failed: %s\n", strerror(errno));
		exit(TEST_ERROR);
	}

	exit(rc);
}
