#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

int main(int argc, char *argv[])
{
	int rc;
	struct stat stat_data;

	rc = stat(argv[1], &stat_data);
	if (rc) {
		printf("rc = [%d]; errno = [%m]\n", rc, errno);
		goto out;
	}
	printf("st_size = [%lu]\n", stat_data.st_size);
out:
	return rc;
}
