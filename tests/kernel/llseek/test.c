/**
 * Author: Michael Halcrow
 *
 * Copyright (C) IBM
 *
 * Modified by Tyler Hicks <tyhicks@canonical.com> to fit into the eCryptfs
 * test modern framework.
 */
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

int main(int argc, char *argv[])
{
	off_t size;
	int fd;
	struct stat s;
	uint32_t deadbeef = 0xdeadbeef;
	uint32_t baadf00d = 0xbaadf00d;
	char *path;
	char buf[4096];
	int i;
	int rc;

	if (argc != 2) {
		fprintf(stderr, "Usage: %s path\n", argv[0]);
		exit(1);
	}
	path = argv[1];

	/* Verifying that lseek() doesn't change the file size */
	fd = open(path, (O_CREAT | O_EXCL| O_WRONLY), S_IRUSR | S_IWUSR);
	if (fd == -1) {
		fprintf(stderr, "Error attempting to create new file [%s]\n",
			path);
		rc = 1;
		goto out;
	}
	size = lseek(fd, 4096, SEEK_END);
	if (size != 4096) {
		fprintf(stderr, "Expected 4096 from lseek; got [%ld]\n", size);
		rc = 1;
		goto out;
	}
	close(fd);
	rc = stat(path, &s);
	if (rc == -1) {
		fprintf(stderr, "Error attempting to stat file [%s]\n",
			path);
		rc = 1;
		goto out;
	}
	if (s.st_size != 0) {
		fprintf(stderr, "Filesize is [%ld]; expected 0\n", s.st_size);
		rc = 1;
		goto out;
	}
	unlink(path);

	/**
	 * Verifying that intermediate regions of the file are initialized to 0
	 * on lseek() and write() events\n;
	 */
	fd = open(path, (O_CREAT | O_EXCL| O_RDWR), S_IRWXU);
	if (fd == -1) {
		fprintf(stderr, "Error attempting to create new file [%s]\n",
			path);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 4096, SEEK_END)) != 4096) {
		fprintf(stderr, "Expected 4096 from lseek; got [%ld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = write(fd, (char *)&deadbeef, 4)) != 4) {
		fprintf(stderr, "Expected a write of 4 bytes; got [%ld] "
			"instead\n", size);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 5120, SEEK_SET)) != 5120) {
		fprintf(stderr, "Expected 5120 from lseek; got [%ld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = write(fd, (char *)&baadf00d, 4)) != 4) {
		fprintf(stderr, "Expected a write of 4 bytes; got [%ld] "
			"instead\n", size);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 4096, SEEK_SET)) != 4096) {
		fprintf(stderr, "Expected 4096 from lseek; got [%ld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 4)) != 4) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&deadbeef, buf, 4) != 0) {
		fprintf(stderr, "deadbeef data mismatch on initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1020)) != 1020) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 1020, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 1020; i++)
		if (buf[i] != 0x00) {
			fprintf(stderr, "Byte [%d] is [0x%.2x]; expected "
				"[0x00]\n", i, buf[i]);
			rc = 1;
			goto out;
		}
	if ((size = read(fd, buf, 4)) != 4) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&baadf00d, buf, 4) != 0) {
		fprintf(stderr, "baadf00d data mismatch on initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1)) != 0) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 0, size);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 0, SEEK_SET)) != 0) {
		fprintf(stderr, "Expected 0 from lseek; got [%ld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 4096)) != 4096) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 4096, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 4096; i++)
		if (buf[i] != 0x00) {
			fprintf(stderr, "Byte [%d] is [0x%.2x]; expected "
				"[0x00]\n", i, buf[i]);
			rc = 1;
			goto out;
		}
	close(fd);
	rc = stat(path, &s);
	if (rc == -1) {
		fprintf(stderr, "Error attempting to stat file [%s]\n",
			path);
		rc = 1;
		goto out;
	}
	if (s.st_size != 5124) {
		fprintf(stderr, "Filesize is [%ld]; expected 5124\n",
			s.st_size);
		rc = 1;
		goto out;
	}
	fd = open(path, (O_RDONLY));
	if (fd == -1) {
		fprintf(stderr, "Error attempting to create new file [%s]\n",
			path);
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 4096)) != 4096) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 4096, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 4096; i++)
		if (buf[i] != 0x00) {
			fprintf(stderr, "Byte [%d] is [0x%.2x]; expected "
				"[0x00]\n", i, buf[i]);
			rc = 1;
			goto out;
		}
	if ((size = read(fd, buf, 4)) != 4) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&deadbeef, buf, 4) != 0) {
		fprintf(stderr, "deadbeef data mismatch after initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1020)) != 1020) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 1020, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 1020; i++)
		if (buf[i] != 0x00) {
			fprintf(stderr, "Byte [%d] is [0x%.2x]; expected "
				"[0x00]\n", i, buf[i]);
			rc = 1;
			goto out;
		}
	if ((size = read(fd, buf, 4)) != 4) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&baadf00d, buf, 4) != 0) {
		fprintf(stderr, "baadf00d data mismatch after initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1)) != 0) {
		fprintf(stderr, "Error attempting to read data. Expected "
			"[%d] bytes; read [%ld] instead\n", 0, size);
		rc = 1;
		goto out;
	}
	close(fd);
	unlink(path);
	rc = 0;
out:
	return rc;
}
