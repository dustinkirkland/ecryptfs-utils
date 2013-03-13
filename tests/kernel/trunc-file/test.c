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

#define SEED		(0xdeadbeef)
#define BUFF_SZ 	(65536)

#define DEFAULT_SIZE	(64*1024)

int write_buff(int fd, unsigned char *data, ssize_t size)
{
	char *ptr = data;
	ssize_t n;
	ssize_t sz = size;

	while (sz > 0) {
		n = write(fd, ptr, sz);
		if (n < 0)
			return -1;
		sz -= n;
		ptr += n;
	}
	return size;
}

int read_buff(int fd, unsigned char *data, ssize_t size)
{
	char *ptr = data;
	ssize_t n;
	ssize_t sz = size;

	while (sz > 0) {
		n = read(fd, ptr, sz);
		if (n <= 0)
			return -1;
		sz -= n;
		ptr += n;
	}
	return size;
}

int test_write_random(char *filename, int fd, unsigned char *buff, ssize_t size)
{
	ssize_t buflen;

	srandom((unsigned int)SEED);
	buflen = size;
	while (buflen > 0) {
		int j;
		ssize_t n = (buflen > BUFF_SZ) ? BUFF_SZ : buflen;

		for (j = 0; j < n; j++)
			buff[j] = random() & 0xff;

		if (write_buff(fd, buff, n) < 0) {
			close(fd);
			return TEST_FAILED;
		}
		buflen -= n;
	}
}

int test_read_random(char *filename, int fd, unsigned char *buff, ssize_t size)
{
	ssize_t buflen;

	if (lseek(fd, 0, SEEK_SET) < 0) {
		fprintf(stderr, "seek failed: %s: %s\n", filename, strerror(errno));
		return -1;
	}

	srandom((unsigned int)SEED);
	buflen = size;
	while (buflen > 0) {
		int j;
		ssize_t n = (buflen > BUFF_SZ) ? BUFF_SZ : buflen;

		if (read_buff(fd, buff, n) < n) {
			fprintf(stderr, "read failed: %s %s\n", filename, strerror(errno));
			return -1;
		}

		for (j = 0; j < n; j++) {
			unsigned char val = random() & 0xff;
			if (buff[j] != val) {
				fprintf(stderr, "Byte %d different from expected value: %d vs %d\n",
					j, val, buff[j]);
				return -1;
			}
		}
		buflen -= n;
	}
	return 0;
}

int test_read_rest(char *filename, int fd, unsigned char *buff, ssize_t trunc_size, size_t size)
{
	ssize_t buflen;

	if (lseek(fd, trunc_size, SEEK_SET) < 0) {
		fprintf(stderr, "seek failed: %s: %s\n", filename, strerror(errno));
		return -1;
	}

	buflen = size - trunc_size;
	while (buflen > 0) {
		int j;
		ssize_t n = (buflen > BUFF_SZ) ? BUFF_SZ : buflen;

		if (read_buff(fd, buff, n) < n) {
			fprintf(stderr, "read failed: %s %s\n", filename, strerror(errno));
			return -1;
		}

		for (j = 0; j < n; j++) {
			if (buff[j] != 0) {
				fprintf(stderr, "Byte %d different from expected value: %d vs %d\n",
					j, 0, buff[j]);
				return -1;
			}
		}
		buflen -= n;
	}
	return 0;
}

int test_exercise(char *filename, ssize_t size)
{
	int fd;
	ssize_t i;
	ssize_t n;
	ssize_t buflen;
	int ret = TEST_FAILED;
	ssize_t trunc_size = size / 2;
	struct stat statbuf;

	unsigned char buff[BUFF_SZ];

	unlink(filename);
	if ((fd = open(filename, O_RDWR | O_CREAT, 0600)) < 0) {
		fprintf(stderr, "Failed to open %s: %s\n", filename, strerror(errno));
		return TEST_FAILED;
	}

	/* Fill with random data */
	if (test_write_random(filename, fd, buff, size) < 0)
		goto done;

	/* Read it back sanity check */
	if (test_read_random(filename, fd, buff, size) < 0)
		goto done;

	/* Iteratively truncate file down */
	while (trunc_size > 0) {
		/* Truncate */
		if (ftruncate(fd, (off_t)trunc_size) < 0) {
			fprintf(stderr, "ftruncate failed: %s %s\n", filename, strerror(errno));
			goto done;
		}

		/* Read check the truncated data again */
		if (test_read_random(filename, fd, buff, trunc_size) < 0)
			goto done;

		/* Check the size */
		if (fstat(fd, &statbuf) < 0) {
			fprintf(stderr, "fstat failed: %s %s\n", filename, strerror(errno));
			goto done;
		}
		if (statbuf.st_size != (off_t)trunc_size) {
			fprintf(stderr, "truncated file size incorrect, got %lu, expected %lu\n",
				(unsigned long)statbuf.st_size, (unsigned long)trunc_size);
			goto done;
		}

		/* Extend to full size using truncate, end is now zero */
		if (ftruncate(fd, (off_t)size) < 0) {
			fprintf(stderr, "ftruncate failed: %s %s\n", filename, strerror(errno));
			goto done;
		}

		/* Check the size */
		if (fstat(fd, &statbuf) < 0) {
			fprintf(stderr, "fstat failed: %s %s\n", filename, strerror(errno));
			goto done;
		}
		if (statbuf.st_size != (off_t)size) {
			fprintf(stderr, "truncated file size incorrect, got %lu, expected %lu\n",
				(unsigned long)statbuf.st_size, (unsigned long)size);
			goto done;
		}

		/* Check the first chunk */
		if (test_read_random(filename, fd, buff, trunc_size) < 0)
			goto done;
		/* Check the end is all zero */
		if (test_read_rest(filename, fd, buff, trunc_size, size) < 0)
			goto done;

		trunc_size >>= 1;
	}

	ret = TEST_PASSED;

done:
	if (close(fd) < 0) {
		fprintf(stderr, "close failed: %s: %s\n", filename, strerror(errno));
		return TEST_FAILED;
	}

	if (unlink(filename) < 0) {
		fprintf(stderr, "unlink failed: %s: %s\n", filename, strerror(errno));
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
		fprintf(stderr, "Syntax: %s filename [size_in_K]\n", argv[0]);
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
	if (len > SSIZE_MAX) {
		fprintf(stderr, "size should be < %zd\n", (ssize_t)SSIZE_MAX / 1024);
		exit(TEST_ERROR);
	}

	signal(SIGINT, sighandler);

	exit(test_exercise(argv[1], (ssize_t)len));
}
