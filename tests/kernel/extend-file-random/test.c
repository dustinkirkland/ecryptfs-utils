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

#define	TEST_PASSED	(0)
#define	TEST_FAILED	(1)
#define TEST_ERROR	(2)

/*
 *  Attempt to create a file with lots of holes, a bit like downloading
 *  an ISO with a torrent client with many multiple random writes
 */
#define BUF_SZ	32

#define DEFAULT_SIZE	(660*1024)	/* CD-ROM Size */

int test_write(int fd, char *buffer, size_t len, off_t offset)
{
	if (lseek(fd, offset, SEEK_SET) < 0) {
		fprintf(stderr, "Failed to seek to position %lu: %s\n", 
			offset, strerror(errno));
		return TEST_FAILED;
	}

	if (write(fd, buffer, len) != len) {
		fprintf(stderr, "Failed to write %zu bytes, position %lu: %s\n", 
			len, offset, strerror(errno));
		return TEST_FAILED;
	}
	return TEST_PASSED;
}

int test_read(int fd, char *buffer, size_t len, off_t offset)
{
	if (lseek(fd, offset, SEEK_SET) < 0) {
		fprintf(stderr, "Failed to seek to position %lu: %s\n", 
			offset, strerror(errno));
		return TEST_FAILED;
	}

	if (read(fd, buffer, len) != len) {
		fprintf(stderr, "Failed to read %zu bytes, position %lu: %s\n", 
			len, offset, strerror(errno));
		return TEST_FAILED;
	}
	return TEST_PASSED;
}

int test_write_read(int fd, char *buffer1, size_t len, off_t offset)
{
	char buffer2[BUF_SZ];
	int ret;

	memset(buffer2, 0, BUF_SZ);

	if ((ret = test_write(fd, buffer1, BUF_SZ, offset)) != 0)
		return ret;
	
	if ((ret = test_read(fd, buffer2, BUF_SZ, offset)) != 0)
		return ret;

	if (memcmp(buffer1, buffer2, BUF_SZ)) {
		fprintf(stderr, "Data read is not same as data written, offset = %lu", offset);
		return TEST_FAILED;
	}
	return TEST_PASSED;
}

int test_exercise(char *filename, off_t max_offset, char data)
{
	int fd;
	int i;
	int ret = TEST_FAILED;
	struct stat statbuf;

	char buffer1[BUF_SZ];
	memset(buffer1, data, BUF_SZ);

	srandom((unsigned int)max_offset);

	unlink(filename);
	if ((fd = open(filename, O_RDWR | O_CREAT, 0600)) < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
		return TEST_FAILED;
	}

	if (test_write_read(fd, buffer1, BUF_SZ, 0))
		goto finish;

	for (i=0; i<8192; i++) {
		off_t offset = (off_t)random() % max_offset;

		if (test_write_read(fd, buffer1, BUF_SZ, offset))
			goto finish;
	}

	if (test_write_read(fd, buffer1, BUF_SZ, max_offset))
		goto finish;

	srandom((unsigned int)max_offset);
	for (i=0; i<8192; i++) {
		char buffer2[BUF_SZ];
		off_t offset = (off_t)random() % max_offset;

		if (test_read(fd, buffer2, BUF_SZ, offset))
			goto finish;

		if (memcmp(buffer1, buffer2, BUF_SZ)) {
			fprintf(stderr, "Data read is not same as data written, offset = %lu", offset);
			goto finish;
		}
	}

	if (fstat(fd, &statbuf) < 0) {
		fprintf(stderr, "Failed to fstat file %s: %s\n", filename, strerror(errno));
		goto finish;
	}

	if (statbuf.st_size != max_offset + BUF_SZ) {
		fprintf(stderr, "Filesize was %lu and not %lu\n", statbuf.st_size, max_offset + BUF_SZ);
		goto finish;
	}

	ret = TEST_PASSED;
finish:
	if (close(fd) < 0) {
		fprintf(stderr, "Failed to close %s: %s\n", filename, strerror(errno));
		return TEST_FAILED;
	}

	if (unlink(filename) < 0) {
		fprintf(stderr, "Failed to unlink %s: %s\n", filename, strerror(errno));
		return TEST_FAILED;
	}

	return ret;
}

void sighandler(int dummy)
{
	exit(TEST_ERROR);
}

int main(int argc, char **argv)
{
	off_t len = DEFAULT_SIZE;
	int i;
	int ret;

	if (argc < 2) {
		fprintf(stderr, "Syntax: filename [size_in_K]\n");
		exit(TEST_ERROR);
	}

	if (argc == 3) {
		len = atoll(argv[2]);
		if (len < 1) {
			fprintf(stderr, "size should be > 0\n");
			exit(TEST_ERROR);
		}
	}
	len *= 1024;

	signal(SIGINT, sighandler);

	for (i=0; i < 2; i++) {
		ret = test_exercise(argv[1], len, i + '@');	
		if (ret != TEST_PASSED) 
			exit(ret);
	}
	exit(TEST_PASSED);
}
