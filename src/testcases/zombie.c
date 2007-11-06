#include <stdio.h>
#include <ecryptfs.h>

int main()
{
	int rc;

	if (fork() == 0) {
		printf("Setting placeholder\n");
		if ((rc = ecryptfs_set_zombie_session_placeholder())) {
			printf("Error setting zombie placeholder; rc = [%d]\n", rc);
			goto out;
		}
		exit(1);
	}
	sleep(5);
	printf("Listing placeholders\n");
	if ((rc = ecryptfs_list_zombie_session_placeholders())) {
		printf("Error listing zombie placeholders; rc = [%d]\n", rc);
		goto out;
	}
	sleep(1);
	printf("Killing and clearing placeholder\n");
	if ((rc = ecryptfs_kill_and_clear_zombie_session_placeholder())) {
		printf("Error killing and clearing zombie placeholder; "
		       "rc = [%d]\n", rc);
		goto out;
	}
	sleep(1);
	printf("Listing placeholder\n");
	if ((rc = ecryptfs_list_zombie_session_placeholders())) {
		printf("Error listing zombie placeholders; rc = [%d]\n", rc);
		goto out;
	}
out:
	return rc;
}
