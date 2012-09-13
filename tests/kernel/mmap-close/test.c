/*
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
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA
 */

#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <unistd.h>
#include <string.h>

#define MEM_LEN		(4096*8)
#define MEM_CHUNK	(4096)

int main(int argc, char **argv)
{
	void *mem;
	int i, fd, rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s FILE_PATH\n", argv[0]);
		return EINVAL;
	}

	fd = open(argv[1], O_RDWR | O_TRUNC | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd < 0) {
		perror("open");
		return errno;
	}

	rc = ftruncate(fd, MEM_LEN);
	if (rc < 0) {
		perror("ftruncate");
		return errno;
	}

	mem = mmap(NULL, MEM_LEN, PROT_WRITE, MAP_SHARED, fd, 0);
	if (mem == MAP_FAILED) {
		perror("mmap");
		return errno;
	}

	/**
	 * This is the crux of the problem: close() before pages are dirtied
	 * and munmap() is called.
	 */
	close(fd);

	for (i = 0; i < MEM_LEN; i += MEM_CHUNK)
		memset(((char *)mem) + i, 0xFF, MEM_CHUNK);

	rc = munmap(mem, MEM_LEN);
	if (rc < 0) {
		perror("munmap");
		return errno;
	}

	return 0;
}
