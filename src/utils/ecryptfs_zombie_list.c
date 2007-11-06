#include "config.h"
#include <stdio.h>
#include <ecryptfs.h>

int main()
{
	int rc;

	if ((rc = ecryptfs_list_zombie_session_placeholders())) {
		printf("Error listing zombie placeholders; rc = [%d]\n", rc);
		goto out;
	}
out:
	return rc;
}
