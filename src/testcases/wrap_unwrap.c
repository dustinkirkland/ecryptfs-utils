#include <stdio.h>
#include <string.h>
#include <ecryptfs.h>

#define FILENAME "wrap.dat"

int main(int argc, char *argv[])
{
	char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 8];
	int passphrase_size;
	char decrypted_passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH + 1];
	int decrypted_passphrase_size;
	char salt[ECRYPTFS_SALT_SIZE + 1];
	int i, j;
	int rc = 0;

	/* Sanity check */
	from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	memcpy(passphrase, "012345679abcdef0\0", 17);
	passphrase_size = strlen(passphrase);
	if ((rc = ecryptfs_wrap_passphrase(FILENAME, "testwrappw", salt,
					   passphrase))) {
		printf("ecryptfs_wrap_passphrase() returned rc = [%d]\n", rc);
		rc = 1;
		goto out;
	}
	if ((rc = ecryptfs_unwrap_passphrase(decrypted_passphrase, FILENAME,
					     "testwrappw", salt))) {
		printf("ecryptfs_unwrap_passphrase() returned rc = [%d]\n", rc);
		rc = 1;
		goto out;
	}
	decrypted_passphrase_size = strlen(decrypted_passphrase);
	if (decrypted_passphrase_size != passphrase_size) {
		printf("Invalid decrypted size [%d]; expected [%d]\n",
		       decrypted_passphrase_size, passphrase_size);
		rc = 1;
		goto out;
	}
	if (memcmp(decrypted_passphrase, passphrase, passphrase_size) != 0) {
		printf("decrypted passphrase = [%s]; expected [%s]\n",
		       decrypted_passphrase, passphrase);
		rc = 1;
		goto out;
	}
	/* Comprehensive check */
	from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	for (i = 0; i < ECRYPTFS_MAX_PASSWORD_LENGTH; i++) {
		passphrase[i] = 'a' + i;
		passphrase[i + 1] = '\0';
		if ((rc = ecryptfs_wrap_passphrase(FILENAME, "testwrappw", salt,
						   passphrase))) {
			printf("ecryptfs_wrap_passphrase() returned "
			       "rc = [%d]\n", rc);
			rc = 1;
			goto out;
		}
		if ((rc = ecryptfs_unwrap_passphrase(decrypted_passphrase,
						     FILENAME,
						     "testwrappw", salt))) {
			printf("ecryptfs_unwrap_passphrase() returned rc = "
			       "[%d]\n", rc);
			rc = 1;
			goto out;
		}
		decrypted_passphrase_size = strlen(decrypted_passphrase);
		if (decrypted_passphrase_size != (i + 1)) {
			printf("Invalid decrypted size [%d]; expected [%d]\n",
			       decrypted_passphrase_size, (i + 1));
			rc = 1;
			goto out;
		}
		if (memcmp(decrypted_passphrase, passphrase, (i + 1)) != 0) {
			printf("decrypted passphrase = [%s]; expected [%s]\n",
			       decrypted_passphrase, passphrase);
			rc = 1;
			goto out;
		}
	}
	/* Failure check */
	from_hex(salt, ECRYPTFS_DEFAULT_SALT_HEX, ECRYPTFS_SALT_SIZE);
	for (i = 0; i < 65; i++)
		passphrase[i] = 'a' + i;
	passphrase[66] = '\0';
	passphrase_size = strlen(passphrase);
	if ((rc = ecryptfs_wrap_passphrase(FILENAME, "testwrappw", salt,
					   passphrase)) == 0) {
		printf("ecryptfs_wrap_passphrase() returned rc = 0; expected "
		       "error result instead\n", rc);
		rc = 1;
		goto out;
	}
	rc = 0;
out:
	return rc;
}
