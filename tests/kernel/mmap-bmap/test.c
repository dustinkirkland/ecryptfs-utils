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
#include <fcntl.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <linux/fs.h>

static int *get_blocks(const char *filename, int *num_blocks)
{
	int fd, block_size, i;
	int *blocks;
	struct stat statinfo;

	if ((fd = open(filename, O_RDONLY)) < 0) {
		fprintf(stderr, "Cannot open %s\n", filename);
		return NULL;
	}

	if (ioctl(fd, FIGETBSZ, &block_size) < 0) {
		fprintf(stderr, "Cannot get block size\n");
		close(fd);
		return NULL;
	}

	if (fstat(fd, &statinfo) < 0) {
		fprintf(stderr, "Cannot stat %s\n", filename);
		close(fd);
		return NULL;
	}

	*num_blocks = (statinfo.st_size + block_size - 1) / block_size;

	blocks = malloc(sizeof(int) * *num_blocks);
	if (!blocks) {
		fprintf(stderr, "Cannot allocate buffer for %d blocks\n", *num_blocks);
		close(fd);
		return NULL;
	}

	/*
	 *  Collect blocks, some file systems may not support FIBMAP, so
	 *  silently ignore errors.
	 */
	for (i = 0; i < *num_blocks; i++) {
		blocks[i] = i;
		if (ioctl(fd, FIBMAP, &blocks[i]) < 0)
			blocks[i] = 0;
	}
	close(fd);

	return blocks;
}

int check_blocks(
	int *lower_blocks, int lower_num_blocks,
	int *upper_blocks, int upper_num_blocks)
{
	int i, j;

	/*  Upper must not have more blocks than lower */
	if (upper_num_blocks > lower_num_blocks)
		return EXIT_FAILURE;

	/*  Upper must have blocks that are in the lower */
	for (i = 0; i < upper_num_blocks; i++) {
		bool found = false;
		for (j = 0; j < lower_num_blocks; j++) {
			if (upper_blocks[i] == lower_blocks[j]) {
				found = true;
				break;
			}
		}
		if (!found)
			return EXIT_FAILURE;
	}
	return EXIT_SUCCESS;
}

int main(int argc, char **argv) {

	int *lower_blocks, *upper_blocks;
	int lower_num_blocks, upper_num_blocks;
	int rc = EXIT_SUCCESS;

	if (argc != 3) {
		fprintf(stderr, "Usage: %s lower-file upper-file\n", argv[0]);
		exit(EXIT_FAILURE);
	}

	lower_blocks = get_blocks(argv[1], &lower_num_blocks);
	if (!lower_blocks)
		exit(EXIT_FAILURE);

	upper_blocks = get_blocks(argv[2], &upper_num_blocks);
	if (!upper_blocks) {
		free(lower_blocks);
		exit(EXIT_FAILURE);
	}

	rc = check_blocks(lower_blocks, lower_num_blocks,
			  upper_blocks, upper_num_blocks);

	free(upper_blocks);
	free(lower_blocks);

	exit(rc);
}
