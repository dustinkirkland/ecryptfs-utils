#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define FILENAME "test.dat"

int main()
{
	off_t size;
	int fd;
	struct stat s;
	uint32_t deadbeef = 0xdeadbeef;
	uint32_t baadf00d = 0xbaadf00d;
	char buf[4096];
	int i;
	int rc;

	printf("Verifying that lseek() doesn't change the file size\n");
	unlink(FILENAME);
	fd = open(FILENAME, (O_CREAT | O_EXCL| O_WRONLY));
	if (fd == -1) {
		printf("Error attempting to create new file [%s]\n", FILENAME);
		rc = 1;
		goto out;
	}
	size = lseek(fd, 4096, SEEK_END);
	if (size != 4096) {
		printf("Expected 4096 from lseek; got [%lld]\n", size);
		rc = 1;
		goto out;
	}
	close(fd);
	rc = stat(FILENAME, &s);
	if (rc == -1) {
		printf("Error attempting to stat file [%s]\n", FILENAME);
		rc = 1;
		goto out;
	}
	if (s.st_size != 0) {
		printf("Filesize is [%lld]; expected 0\n", s.st_size);
		rc = 1;
		goto out;
	}
	unlink(FILENAME);

	printf("Verifying that intermediate regions of the file are "
	       "initialized to 0 on lseek() and write() events\n");
	fd = open(FILENAME, (O_CREAT | O_EXCL| O_RDWR), S_IRWXU);
	if (fd == -1) {
		printf("Error attempting to create new file [%s]\n", FILENAME);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 4096, SEEK_END)) != 4096) {
		printf("Expected 4096 from lseek; got [%lld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = write(fd, (char *)&deadbeef, 4)) != 4) {
		printf("Expected a write of 4 bytes; got [%lld] instead\n",
		       size);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 5120, SEEK_SET)) != 5120) {
		printf("Expected 5120 from lseek; got [%lld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = write(fd, (char *)&baadf00d, 4)) != 4) {
		printf("Expected a write of 4 bytes; got [%lld] instead\n",
		       size);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 4096, SEEK_SET)) != 4096) {
		printf("Expected 4096 from lseek; got [%lld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 4)) != 4) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&deadbeef, buf, 4) != 0) {
		printf("deadbeef data mismatch on initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1020)) != 1020) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 1020, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 1020; i++)
		if (buf[i] != 0x00) {
			printf("Byte [%d] is [0x%.2x]; expected [0x00]\n", i,
				buf[i]);
			rc = 1;
			goto out;
		}
	if ((size = read(fd, buf, 4)) != 4) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&baadf00d, buf, 4) != 0) {
		printf("baadf00d data mismatch on initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1)) != 0) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 0, size);
		rc = 1;
		goto out;
	}
	if ((size = lseek(fd, 0, SEEK_SET)) != 0) {
		printf("Expected 0 from lseek; got [%lld]\n", size);
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 4096)) != 4096) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 4096, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 4096; i++)
		if (buf[i] != 0x00) {
			printf("Byte [%d] is [0x%.2x]; expected [0x00]\n", i,
				buf[i]);
			rc = 1;
			goto out;
		}
	close(fd);
	rc = stat(FILENAME, &s);
	if (rc == -1) {
		printf("Error attempting to stat file [%s]\n", FILENAME);
		rc = 1;
		goto out;
	}
	if (s.st_size != 5124) {
		printf("Filesize is [%lld]; expected 5124\n", s.st_size);
		rc = 1;
		goto out;
	}
	fd = open(FILENAME, (O_RDONLY));
	if (fd == -1) {
		printf("Error attempting to create new file [%s]\n", FILENAME);
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 4096)) != 4096) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 4096, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 4096; i++)
		if (buf[i] != 0x00) {
			printf("Byte [%d] is [0x%.2x]; expected [0x00]\n", i,
				buf[i]);
			rc = 1;
			goto out;
		}
	if ((size = read(fd, buf, 4)) != 4) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&deadbeef, buf, 4) != 0) {
		printf("deadbeef data mismatch after initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1020)) != 1020) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 1020, size);
		rc = 1;
		goto out;
	}
	for (i = 0; i < 1020; i++)
		if (buf[i] != 0x00) {
			printf("Byte [%d] is [0x%.2x]; expected [0x00]\n", i,
				buf[i]);
			rc = 1;
			goto out;
		}
	if ((size = read(fd, buf, 4)) != 4) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 4, size);
		rc = 1;
		goto out;
	}
	if (memcmp((char *)&baadf00d, buf, 4) != 0) {
		printf("baadf00d data mismatch after initial write\n");
		rc = 1;
		goto out;
	}
	if ((size = read(fd, buf, 1)) != 0) {
		printf("Error attempting to read data. Expected [%lld] bytes; "
		       "read [%lld] instead\n", 0, size);
		rc = 1;
		goto out;
	}
	close(fd);
	unlink(FILENAME);
	rc = 0;
out:
	return rc;
}
