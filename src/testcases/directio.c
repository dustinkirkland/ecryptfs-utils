#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/sendfile.h>

#define BUF_SIZE 4096

int main(int argc, char *argv[])
{
	char buf[BUF_SIZE];
	ssize_t ssize;
	size_t size;
	int i;
	int fd;
	int out_fd;
	off_t offset;

	if (argc != 2) {
		printf("Usage:\ndirectio <filename>\n");
		return 1;
	}
	printf("Opening file [%s]\n", argv[1]);
	fd = open(argv[1], (O_RDONLY));
	if (fd == -1) {
		printf("Error opening file for direct I/O read; errno = [%d]; "
		       "errno msg = [%m]\n", errno, errno);
		return 1;
	}
	unlink("/tmp/tmp.txt");
	out_fd = open("/tmp/tmp.txt", O_WRONLY | O_CREAT | O_EXCL, 0666);
	if (out_fd == -1) {
		printf("err\n");
		return 1;
	}
	offset = 0;
	ssize = sendfile(out_fd, fd, &offset, 306);
	if (ssize == -1) {
		printf("Error sending file for sendfile; errno = [%d]; "
		       "errno msg = [%m]\n", errno, errno);
		return 1;
	}
	printf("Read [%ld] bytes of data from file\n", ssize);
	close(fd);
}
