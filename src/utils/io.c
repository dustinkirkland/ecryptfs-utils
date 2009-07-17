/**
 * Copyright (C) 2006 International Business Machines
 * Author(s): Trevor Highland <tshighla@us.ibm.com>
 *            Theresa Nelson <tmnelson@us.ibm.com>
 *            Tyler Hicks <tyhicks@ou.edu>
 *
 * I/O functions for mount helper
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

#include <stdio.h>
#include <string.h>
#include <termios.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/mman.h>
#include "config.h"
#include "ecryptfs.h"
#include "io.h"

static int disable_echo(struct termios *saved_settings)
{
	struct termios current_settings;
	int rc = 0;

	rc = tcgetattr(0, &current_settings);
	if (rc)
		return rc;
	*saved_settings = current_settings;
	current_settings.c_lflag &= ~ECHO;
	rc = tcsetattr(0, TCSANOW, &current_settings);
	return rc;
}

static int enable_echo(struct termios *saved_settings)
{
	return tcsetattr(0, TCSANOW, saved_settings);
}

int mygetchar(void)
{
	int c = getchar();

	if (c == '\r')
		c = '\n';
	return c;
}

int get_string_stdin(char **val, char *prompt, int echo)
{
#define DEFAULT_STRING_LENGTH 16
	int count = 0;
	struct termios saved_settings;
	int length = DEFAULT_STRING_LENGTH;
	char *temp;
	int rc = 0;
	int c;

	printf("%s: ", prompt);
	temp = malloc(length);
	if (!temp) {
		rc = -ENOMEM;
		goto out;
	}
	temp[0] = '\0';
	*val = temp;
	if (!echo) {
		rc = disable_echo(&saved_settings);
		if (rc)
			goto out;
	}
	do {
		if (count == length) {
			temp = malloc(length * 2);
			if (!temp) {
				rc = -ENOMEM;
				goto out;
			}
			memcpy(temp, *val, length);
			memset(*val, 0, length);
			length *= 2;
			free(*val);
			*val = temp;
		}
		if ((c = mygetchar()) != EOF)
			(*val)[count] = c;
		else 
			(*val)[count] = '\n';
		count++;
	} while(c != EOF && (*val)[count-1] != '\n');
	(*val)[count - 1] = '\0';
	if (!echo) {
		printf("\n");
		rc = enable_echo(&saved_settings);
	}
	if (count == 1 && c == EOF) {
		free(*val);
		*val = NULL;
		rc = -EIO;
	}
out:
	return rc;
}

int get_string(char *val, int len, int echo)
{
	int count = 0;
	struct termios saved_settings;
	int rc = 0;
	int c;

	if (echo == ECRYPTFS_ECHO_OFF) {
		rc = disable_echo(&saved_settings);
		if (rc)
			goto out;
	}
	do {
		if ((c = mygetchar()) != EOF)
			val[count] = c;
		else 
			val[count] = '\n';
		count++;
	} while(c != EOF && val[count-1] != '\n' && (count < len));
	if (echo == ECRYPTFS_ECHO_OFF) {
		printf("\n");
		rc = enable_echo(&saved_settings);
	}
	if (count == 1 && c == EOF) {
		*val = '\0';
		rc = -EIO;
	} else if (count > len)
		val[len - 1] = '\0';
	else
		val[count - 1] = '\0';
out:
	return rc;
}

static inline int munch_newline(void)
{
	int c;
	if ((c=mygetchar()) == '\n' || c == EOF)
		return 0;
	while ((c=mygetchar()) != '\n' && c != EOF);
	return -1;
}

int manager_menu(void)
{
	char str[8];
	int selection;

	printf("\neCryptfs key management menu\n");
	printf("-------------------------------\n");
	printf("\t%d. Add passphrase key to keyring\n", MME_MOUNT_PASSPHRASE);
	printf("\t%d. Add public key to keyring\n", MME_MOUNT_PUBKEY);
	printf("\t%d. Generate new public/private keypair\n", MME_GEN_PUBKEY);
	printf("\t%d. Exit\n", MME_ABORT);
try_again:
	printf("\nMake selection: ");
	str[0] = mygetchar();
	if (munch_newline()) {
		printf("Invalid selection\n");
		goto try_again;
	}
	str[strlen(str)] = '\0';
	selection = atoi(str);
	switch (selection) {
	case MME_MOUNT_PASSPHRASE:
	case MME_MOUNT_PUBKEY:
	case MME_GEN_PUBKEY:
	case MME_ABORT:
		break;
	default:
		printf("Invalid selection\n");
		goto try_again;
	}
	return selection;
}

int read_passphrase_salt(char *pass, char *salt)
{
	char *confirmed_pass;
	int rc = 0;

	confirmed_pass = malloc(ECRYPTFS_MAX_PASSWORD_LENGTH);
	if (!confirmed_pass) {
		rc = -ENOMEM;
		ecryptfs_syslog(LOG_ERR, "Failed to allocate memory\n");
		goto out;
	}
	mlock(confirmed_pass, ECRYPTFS_MAX_PASSWORD_LENGTH);
	printf("\n\tMount-wide passphrase: ");
	rc = get_string(pass, ECRYPTFS_MAX_PASSWORD_LENGTH, ECRYPTFS_ECHO_OFF);
	if (rc)
		goto out;
	if (pass[0] == '\0') {
		printf("Invalid passphrase. Aborting mount.\n");
		rc = -EINVAL;
		goto out;
	}
	printf("\tConfirm passphrase: ");
	rc = get_string(confirmed_pass, ECRYPTFS_MAX_PASSWORD_LENGTH,
			ECRYPTFS_ECHO_OFF);
	if (rc) {
		ecryptfs_syslog(LOG_ERR, "Failed to read passphrase\n");
		goto out;
	}
	if (strcmp(pass, confirmed_pass) != 0) {
		printf("Passphrase mismatch. Aborting mount\n");
		rc = -EINVAL;
		goto out;
	}
	printf("\tUsing the default salt value\n");
out:
	memset(confirmed_pass, 0, ECRYPTFS_MAX_PASSWORD_LENGTH);
	free(confirmed_pass);
	return rc;
}

int ecryptfs_select_key_mod(struct ecryptfs_key_mod **key_mod,
			    struct ecryptfs_ctx *ctx)
{
        int rc;
        int key_mod_type;
        int count;
        struct ecryptfs_key_mod *curr;
        char str[8];
	int default_key_mod = 1;

prompt_user:
        count = 1;
        curr = ctx->key_mod_list_head.next;
        if (!curr) {
                rc = 1;
                goto out;
        }
        if (!(curr->next))
                goto success;
	printf("\nThe following PKI modules are available:\n");
        while (curr) {
                printf("\t%i. %s\n", count, curr->alias);
                count++;
                curr = curr->next;
        }
	printf("\nSelect desired key module [%d]: ", default_key_mod);
	if (fgets(str, 4, stdin) == NULL) {
		printf("\nError reading input\n");
		rc = -EIO;
		goto out;
	}
	printf("\n");
        str[strlen(str)] = '\0';
	if (str[0] == '\n')
		key_mod_type = default_key_mod;
	else
		key_mod_type = atoi(str);
        if (key_mod_type < 1 || key_mod_type >= count) {
                char *pch = strstr(str, "\n");

                printf("Invalid selection\n");
                if (!pch) {
                        int ch;

                        while ((ch = mygetchar()) != '\n' && ch != EOF);
                }
                goto prompt_user;
        }
        curr = ctx->key_mod_list_head.next;
        while(key_mod_type > 1) {
                curr = curr->next;
                key_mod_type--;
        }
success:
	(*key_mod) = curr;
        rc = 0;
out:
        return rc;
}
