#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	char *filename;
	int fd;
	int i;
	int iterations;
	int do_close = 1;
	int rc;

	if (argc < 3) {
		printf("Usage: open_close <path> [iterations]\n");
		return 1;
	}
	iterations = atoi(argv[2]);
	if (argc == 4)
		do_close = 0;
	printf("file base [%s]; iterations = [%d]\n", argv[1], iterations);
	for (i = 0; i < iterations; i++) {
		rc = asprintf(&filename, "%s/file%d", argv[1], i);
		if (rc == -1) {
			printf("Out of memory\n");
			return 1;
		}
		fd = open(filename, (O_CREAT | O_EXCL));
		if (fd == -1) {
			printf("Error creating file [%s]; errno = [%d]; "
			       "string = [%s].  Died on iteration [%d].\n",
			       filename, errno, strerror(errno), i);
			return 1;
		}
		if (do_close)
			close(fd);
		rc = unlink(filename);
		if (rc == -1) {
			printf("Error unlinking file [%s]; errno = [%d]; "
			       "string = [%s]\n", filename, errno,
			       strerror(errno));
		}
		free(filename);	
	}
	return 0;
}
