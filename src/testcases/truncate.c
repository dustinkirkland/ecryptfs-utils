#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>
#include <stdlib.h>

int main(int argc, char **argv)
{
	int fd;
	struct stat *fstat;
	char *filename;
	ssize_t size;

	if (argc < 2) {
		printf("Usage: test_truncate <path>\n");
		return 1;
	}
	filename = argv[1];
	fd = open(filename, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		printf("error opening file\n");
		return 1;
	}
	size = write(fd , "abc" , 3);
	if (size < 0) {
		printf("data not written to file");
		return 1;
	}
	if ((close(fd) != 0)) {
		printf("error closing file");
		return 1;
	}
	fd = open(filename, O_RDWR | O_TRUNC, S_IRUSR | S_IWUSR);
	if (fd == -1) {
		printf("2 error opening file\n");
		return 1;
	}
	if ((close(fd) != 0)) {
		printf("2 error closing file");
		return 1;
	}
	fstat = malloc(sizeof(struct stat));
	if (!fstat) {
		printf("Unable to allocate memory\n");
		return 1;
	}
	stat(filename, fstat);
	if (fstat->st_size != 0) {
		printf("test file should be 0 bytes\n");
		printf("test file is [%d] bytes\n", fstat->st_size);
		free(fstat);
		if (unlink(filename)) {
			printf("error deleting file\n");
			return 1;
		}
		return 1;
	}
	free(fstat);
	if (unlink(filename)) {
		printf("error deleting file\n");
		return 1;
	}
	return 0;
}
