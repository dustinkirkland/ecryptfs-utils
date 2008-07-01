/**
 * Present statistics on encrypted eCryptfs file attributes
 */

#include <stdio.h>
#include "../include/ecryptfs.h"

static void usage(const char *filename)
{
	printf("Usage:\n\n"
	       "%s <filename>\n", filename);
}

int main(int argc, const char *argv[])
{
	int rc = 0;

	if (argc == 1) {
		usage(argv[0]);
		goto out;
	}
out:
	return rc;
}
