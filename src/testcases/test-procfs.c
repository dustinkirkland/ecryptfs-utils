#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"

int main()
{
	struct ecryptfs_proc_ctx proc_ctx;
	int fd;
	int rc;

/*	rc = ecryptfs_init_proc(&proc_ctx); */
	printf("opening\n");
	fd = open("/proc/fs/ecryptfs/ctl", O_RDONLY);
	printf("ioctl'ing\n");
	rc = ioctl(fd, SIOCSIFMAP);
	if (rc)
		printf("%s: [%d]\n", __FUNCTION__, rc);
}
