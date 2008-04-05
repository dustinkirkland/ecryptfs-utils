#include <fcntl.h>
#include <errno.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"

int main()
{
	ssize_t ssize;
	struct ecryptfs_proc_ctx proc_ctx;
	char buf[65536];
	int fd;
	int rc;

	rc = ecryptfs_init_proc(&proc_ctx);
	if (rc) {
		printf("%s: [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	ssize = read(proc_ctx.proc_fd, buf, 65536);
	if (ssize == -1) {
		printf("%s: ssize == -1; errno msg = [%m]\n", __FUNCTION__,
		       errno);
	} else {
		printf("%s: Read [%d] bytes\n", __FUNCTION__, ssize);
	}
	ecryptfs_release_proc(&proc_ctx);
out:
	return rc;
}
