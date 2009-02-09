/**
 * Copyright (C) 2007 International Business Machines
 * Author(s): Michael Halcrow <mhalcrow@us.ibm.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License as
 * published by the Free Software Foundation; either version 2 of the
 * License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA
 * 02111-1307, USA.
 */

#include "config.h"
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>
#include <stdio.h>
#include <stdlib.h>
#include <termios.h>
#include <string.h>
#include <errno.h>
#include "ecryptfs.h"
#include "io.h"

/**
 * TODO: Use decision graph here
 */
int ecryptfs_generate_key(void)
{
	return -EINVAL;
/*	struct ecryptfs_ctx ctx;
	struct ecryptfs_key_mod *key_mod = NULL;
	char *home;
	char *directory;
	char *file;
	uid_t id;
	struct passwd *pw;
	int rc = 0;

	id = getuid();
	pw = getpwuid(id);
	home = pw->pw_dir;
	printf("\n");
	printf("This is the eCryptfs key generation utility. At any time \n"
	       "you may hit enter to selected a default option appearing in \n"
	       "brackets.\n");
	printf("\n");
	if ((rc = ecryptfs_get_key_mod_list(&ctx))) {
		fprintf(stderr, "Error: eCryptfs was unable to initialize the "
				"PKI modules.\n");
		return 0;
	}
	if (ecryptfs_select_key_mod(&key_mod, &ctx)) {
		fprintf(stderr, "Error: Problem loading the selected PKI.\n");
		return 0;
	}
	file = malloc(MAX_PATH_SIZE);
	if (!file) {
		fprintf(stderr, "Out of memory\n");
		return 0;
	}
	printf("\nEnter the filename where the key should be written.\n"
	       "[%s%s%s/key.pem]:", home, "/.ecryptfs/pki/",
	       key_mod->alias);
	get_string(file, MAX_PATH_SIZE, ECHO);
	if (*file == '\0')
		memcpy(file, "key.pem", 8);
	if (*file == '/') {
		rc = key_mod->ops->generate_key(file);
		if (rc) {
			fprintf(stderr, "Error: unable to write key to file\n");
			return 0;
		}
	} else {
		rc = create_default_dir(home, selected_pki);
		if (rc) {
			fprintf(stderr, "Error: unable to create default pki directory\n");
			goto out;
		}
		rc = create_subdirectory(file, home, selected_pki);
		if (rc) {
			fprintf(stderr, "Error: unable to create the desired subdirectories\n");
			goto out;
		}
		rc = asprintf(&directory, "%s/.ecryptfs/pki/%s/%s", home,
			      selected_pki->pki_name, file);
		if (rc == -1) {
			fprintf(stderr, "Out of memory\n");
			rc = 0;
			goto out;
		}
		rc = selected_pki->ops.generate_key(directory);
		if (rc)
			fprintf(stderr, "Error: unable to write key to file\n");
	}
out:
return rc; */
}

int
create_subdirectory(char *file, char *home, struct ecryptfs_key_mod *key_mod)
{
	char *substring;
	char *directory;
	int rc = 0;

	substring = file;
	while((substring = strstr(substring, "/")) != NULL) {
		char temp = *(substring + 1);
		*(substring + 1) = '\0';
		if (asprintf(&directory, "%s/.ecryptfs/pki/%s/%s",
			     home, key_mod->alias, file) < 0) {
			rc = errno;
			fprintf(stderr, "Error: %m\n");
			goto out;
		}
		printf("%s\n",directory);
		if (mkdir(directory,0700) != 0 && errno != EEXIST) {
			rc = errno;
			fprintf(stderr, "Error: %m\n");
			goto out;
		}
               	free(directory);
		*(substring + 1) = temp;
		substring = substring + 1;
	}
out:
	return rc;
}

int create_default_dir(char *home, struct ecryptfs_key_mod *key_mod)
{
	char *directory;
	int rc = 0;

	if (asprintf(&directory, "%s/.ecryptfs/", home) < 0) {
		rc = errno;
		fprintf(stderr, "Error: %m\n");
		goto out;
	}
	if (mkdir(directory,0700) != 0 && errno != EEXIST) {
		rc = errno;
		fprintf(stderr, "Error: %m\n");
		goto out;
	}
	free(directory);
	if (asprintf(&directory, "%s/.ecryptfs/pki/", home) < 0) {
		rc = errno;
		fprintf(stderr, "Error: %m\n");
		goto out;
	}
	if (mkdir(directory,0700) != 0 && errno != EEXIST) {
		rc = errno;
		fprintf(stderr, "Error: %m");
		goto out;
	}
	free(directory);
	if (asprintf(&directory, "%s/.ecryptfs/pki/%s/", home,
		     key_mod->alias) < 0) {
		rc = errno;
		fprintf(stderr, "Error: %m\n");
		goto out;
	}
	if (mkdir(directory,0700) != 0 && errno != EEXIST) {
		rc = errno;
		fprintf(stderr, "Error: %m\n");
		goto out;
	}
	free(directory);
out:
	return rc;
}
