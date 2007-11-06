#include <stdio.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdlib.h>

static char data[] = {
	'a', 'b', 'c', '\0',
	'\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0',
	'\0', '\0', '\0', '\0'
};
#define DATA_SIZE 16

int main(int argc, char *argv[])
{
	int fd;
	struct stat *fstat;
	char *filename;
	ssize_t size;
#define BUF_SIZE 32
	char buf[BUF_SIZE];
	int i;
	int no_open = 0;
	int data_size;
	int rc = 0;

	if (argc < 2) {
		printf("Usage: test_truncate_no_open <path>\n");
		return 1;
	}
	if (argc == 3)
		no_open = 1;
	filename = argv[1];
	printf("Test filename: [%s]\n", filename);
	if (!no_open) {
		unlink(filename);
		if ((fd = open(filename, (O_WRONLY | O_CREAT | O_EXCL),
			       (S_IRUSR | S_IWUSR))) == -1) {
			printf("Error attempting to create empty file [%s]\n",
			       filename);
			rc = 1;
			goto out;
		}
		size = write(fd , "abc" , 3);
		if (size < 0) {
			printf("data not written to file");
			rc = 1;
			goto out;
		}
		close(fd);
		fstat = malloc(sizeof(struct stat));
		if (!fstat) {
			printf("Unable to allocate memory\n");
			rc = 1;
			goto out;
		}
		stat(filename, fstat);
		if (fstat->st_size != 3) {
			printf("test file should be 3 bytes\n");
			printf("test file is [%d] bytes\n", fstat->st_size);
			free(fstat);
			if (unlink(filename)) {
				printf("error deleting file\n");
				rc = 1;
				goto out;
			}
			rc = 1;
			goto out;
		}
		free(fstat);
	}
	if (no_open)
		data_size = DATA_SIZE * 2;
	else
		data_size = DATA_SIZE;
	if ((rc = truncate(filename, data_size)) == -1) {
		printf("Error attempting to truncate [%s] to [%d] bytes\n",
		       filename, data_size);
		rc = 1;
		goto out;
	}
	rc = 0;
	fstat = malloc(sizeof(struct stat));
	if (!fstat) {
		printf("Unable to allocate memory\n");
		rc = 1;
		goto out;
	}
	stat(filename, fstat);
	if (fstat->st_size != data_size) {
		printf("test file should be [%d] bytes\n", data_size);
		printf("test file is [%d] bytes\n", fstat->st_size);
		free(fstat);
		if (unlink(filename)) {
			printf("error deleting file\n");
			rc = 1;
			goto out;
		}
		rc = 1;
		goto out;
	}
	free(fstat);
	if ((fd = open(filename, O_RDONLY)) == -1) {
		printf("Error attempting to open file [%s]\n", filename);
		rc = 1;
		goto out;
	}
	size = read(fd, buf, BUF_SIZE);
	if (size != data_size) {
		printf("expected to read [%d] bytes; read [%d] bytes instead\n",
		       data_size, size);
		rc = 1;
		goto out;
	}
	close(fd);
	for (i = 0; i < data_size; i++)
		if (buf[i] != data[i]) {
			printf("Data at offset [%d] does not match. Expected "
			       "data = [0x%.2x]; read data = [0x%.2x]\n", i,
			       data[i], buf[i]);
			rc = 1;
			goto out;
		}
out:
	if (rc)
		printf("truncate_no_open test failed; rc = [%d]\n", rc);
	else
		printf("truncate_no_open test succeeded\n");
	return rc;
}
