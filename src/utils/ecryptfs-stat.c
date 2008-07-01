/**
 * Present statistics on encrypted eCryptfs file attributes
 */

#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"

static void usage(const char *filename)
{
	printf("Usage:\n\n"
	       "%s <filename>\n", filename);
}

int main(int argc, const char *argv[])
{
	const char *filename;
	int fd = -1;
	ssize_t quant_read;
	struct ecryptfs_crypt_stat_user crypt_stat;
	char buf[4096];
	int rc = 0;

	if (argc == 1) {
		usage(argv[0]);
		goto out;
	}
	filename = argv[1];
	fd = open(filename, O_RDONLY);
	if (fd == -1) {
		printf("Error opening file [%s] for RD_ONLY access; errno msg "
		       "= [%m]\n", filename, errno);
		rc = -EIO;
		goto out;
	}
	quant_read = read(fd, buf, 4096);
	if (quant_read == -1) {
		printf("Error attempting to read from file [%s]; errno msg "
		       "= [%m]\n", filename, errno);
		rc = -EIO;
		goto out;
	}
	rc = ecryptfs_parse_stat(&crypt_stat, buf, quant_read);
	if (rc) {
		printf("Valid eCryptfs metadata information not found in [%s]"
		       "\n", filename);
		rc = 0;
		goto out;
	}
out:
	if (fd != -1)
		close(fd);
	return rc;
}
