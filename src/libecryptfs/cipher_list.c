/**
 * Copyright (C) 2006 International Business Machines Corp.
 * Authors: Trevor Highland <tshighla@us.ibm.com>
 *          Theresa Nelson <tmnelson@us.ibm.com>
 *          Tyler Hicks <tyhicks@ou.edu>
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

#include <dirent.h>
#include <stdlib.h>
#include <string.h>
#ifndef S_SPLINT_S
#include <syslog.h>
#include <stdio.h>
#endif
#include <errno.h>
#include <fcntl.h>
#include <mntent.h>
#ifndef S_SPLINT_S
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/utsname.h>
#endif
#include "config.h"
#include "../include/ecryptfs.h"

#define MAX_BUF_LEN 128

static int get_proc_mount_point(char **proc_mount_point)
{
	FILE *fp;
	struct mntent *mntent;
	int rc = 0;

	fp = fopen("/etc/mtab", "r");
	if (!fp) {
		rc = -errno;
		goto out;
	}
	while ((mntent = getmntent(fp)))
		if (strcmp(mntent->mnt_type, "proc") == 0) {
			asprintf(proc_mount_point, "%s", mntent->mnt_dir);
			fclose(fp);
			goto out;
		}
	rc = -EINVAL;
	fclose(fp);
out:
	return rc;
}

static struct cipher_str_name_map_elem cipher_str_name_map[] = {
	{"aes", "AES-128", 16},
	{"blowfish", "Blowfish", 16},
	{"des3_ede", "Triple-DES", 24},
	{"twofish", "Twofish", 16},
	{"cast5", "CAST5", 16},
	{"cast6", "CAST6", 16},
	{"aes", "AES-192", 24},
	{"aes", "AES-256", 32}
};

static int add_cipher(char *name, struct ecryptfs_cipher_elem **current,
		      uint8_t flag)
{
	int i;
	int rc = 0;
	struct cipher_str_name_map_elem *cipher;

	for(i = 0;
	    i < (sizeof(cipher_str_name_map) / sizeof(*cipher_str_name_map));
	    i++) {
		cipher = &(cipher_str_name_map[i]);
		if(strcmp(name, cipher->kernel_name))
			continue;
		(*current)->next = malloc(sizeof(struct ecryptfs_cipher_elem));
		if ((*current)->next == NULL)
			return -ENOMEM;
		memset((*current)->next, 0, sizeof(struct ecryptfs_cipher_elem));
		(*current) = (*current)->next;
		(*current)->loaded_cipher = flag;
		rc = asprintf(&(*current)->kernel_name, "%s",
			      cipher->kernel_name);
		if (rc == -1)
			return -ENOMEM;
		rc = asprintf(&(*current)->user_name, "%s", cipher->user_name);
		if (rc == -1)
			return -ENOMEM;
		(*current)->bytes = cipher->keysize_bytes;
	}
	return 0;
}

static int get_proc_crypto_value(char *line, char **value)
{
	int len;

	strtok(line, ": ");
	*value = strtok(NULL, ": ");
	if (!(*value))
		return 1;

	len = strlen(*value);
	if ((*value)[len - 1] == '\n')
		(*value)[len - 1] = '\0';

	return 0;
}

int ecryptfs_get_current_kernel_ciphers(
	struct ecryptfs_cipher_elem *cipher_list_head)
{
	int rc;

	if (!(rc = ecryptfs_get_loaded_ciphers(cipher_list_head)))
		rc = ecryptfs_add_crypto_modules(cipher_list_head);
	return rc;
}

/**
 * ecryptfs_get_loaded_cipher - creates a linked list of ciphers in
 * the kernel
 * @cipher_list_head: the head of the cipher list
 *
 * Parses the /proc/crypto file to determine which ciphers are
 * built-in or loaded into the kernel.
 *
 * Returns 0 after a successful read of /proc/cypto, 1 otherwise.
 */
int ecryptfs_get_loaded_ciphers(struct ecryptfs_cipher_elem *cipher_list_head)
{
	FILE *crypto_file = NULL;
	char buf[MAX_BUF_LEN];
	char name[MAX_BUF_LEN];
	char *tmp = NULL;
	char *proc_mount_point = NULL;
	char *crypto_full_path = NULL;
	struct ecryptfs_cipher_elem *current_cipher = cipher_list_head;
	int rc;

	if (!cipher_list_head) {
		rc = -EINVAL;
		goto out;
	}
	rc = get_proc_mount_point(&proc_mount_point);
	if (rc) {
		syslog(LOG_WARNING, "Error attempting to find proc mount "
		       "point in [/etc/mtab]. Defaulting to [/proc].\n");
		rc = 0;
		if (asprintf(&proc_mount_point, "/proc") == -1) {
			proc_mount_point = NULL;
			rc = -ENOMEM;
			goto out;
		}
	}
	if (asprintf(&crypto_full_path, "%s/crypto", proc_mount_point) == -1) {
			crypto_full_path = NULL;
			rc = -ENOMEM;
			goto out;
	}
	if (!(crypto_file = fopen(crypto_full_path, "r"))) {
		rc = -EIO;
		goto out;
	}
	while (fgets(buf, MAX_BUF_LEN, crypto_file)) {
		if (!strncmp(buf, "name", 4)) {
			if (!get_proc_crypto_value(buf, &tmp))
				memcpy(name, tmp, MAX_BUF_LEN);
		}
		else if (!strncmp(buf, "type", 4)) {
			if (get_proc_crypto_value(buf, &tmp))
				continue;
			if (strncmp(tmp, "cipher", 6))
				continue;
			rc = add_cipher(name, &current_cipher, 1);
			if (rc)
				goto out;
		}
	}
out:
	if (crypto_file)
		fclose(crypto_file);
	free(proc_mount_point);
	free(crypto_full_path);
	return rc;
}

/**
 * ecryptfs_add_crypto_modules - adds cyrpt modules to cipher list
 * @cipher_list_head: the head of the cipher list
 *
 * This function determines what kernel is currently being used
 * and then adds available modules to the cipher list for
 * user selection.
 *
 * Returns 0 on a successful read of the /lib/modules/`uname -r`/kernel/crypto
 * directory, 1 otherwise.
 */
int ecryptfs_add_crypto_modules(struct ecryptfs_cipher_elem *cipher_list_head)
{
	DIR *dp;
	int rc = 0;
	char *mod_ext;
	struct dirent *ep;
	struct utsname kern_info;
	char kern_vers[MAX_NAME_SIZE];
	char dir_name[MAX_NAME_SIZE];
	char mod_name[MAX_NAME_SIZE];
	struct ecryptfs_cipher_elem *current_cipher;

	if (uname(&kern_info) == -1)
		return 1;

	strncpy(kern_vers, kern_info.release, MAX_NAME_SIZE);
	strncpy(dir_name, "/lib/modules/", MAX_NAME_SIZE);
	strncat(dir_name, kern_vers, MAX_NAME_SIZE - strlen(dir_name));
	strncat(dir_name, "/kernel/crypto", MAX_NAME_SIZE - strlen(dir_name));

	if (!(dp = opendir(dir_name)))
		return 1;

	while((ep = readdir(dp))) {
		strncpy(mod_name, ep->d_name, MAX_NAME_SIZE);
		if (!(mod_ext = strstr(mod_name, ".ko")))
			continue;
		*mod_ext = '\0';
		if (!strcmp(mod_name, "des\0"))
			strncpy(mod_name, "des3_ede\0", 9);
		current_cipher = cipher_list_head;
		while (current_cipher->next) {
			if (strcmp(current_cipher->next->kernel_name, mod_name))
				current_cipher = current_cipher->next;
			else
				break;
		}
		if (current_cipher->next)
			continue;
		rc = add_cipher(mod_name, &current_cipher, 0);
		if (rc)
			goto out;
	}
out:
	closedir(dp);
	return rc;
}

/*
 * default_cipher - parses the default cipher from the cipher struct
 * @default_cipher: Pointer to cipher selected to be default
 * @keysize: indicates the keysize in bytes of the default cipher
 *
 * This function determines which cipher is the first crosslisted cipher
 * between the available and supported cipher lists. It then returns
 * that name and the keysize of that cipher to function caller.
 * Returns zero on success.
 **/
int ecryptfs_default_cipher(struct ecryptfs_cipher_elem **default_cipher,
		 	    struct ecryptfs_cipher_elem *cipher_list_head)
{
	struct ecryptfs_cipher_elem *current_cipher;
	int i, limit;
	int rc = 0;
	limit = (sizeof(cipher_str_name_map)
		/ sizeof(struct cipher_str_name_map_elem));
	for (i = 0; i < limit; i++) {
		current_cipher = cipher_list_head->next;
		while (current_cipher) {
			if (!strcmp(cipher_str_name_map[i].kernel_name,
						current_cipher->kernel_name)) {
				*default_cipher = current_cipher;
				goto out;
			}
			current_cipher = current_cipher->next;
		}
	}
	rc = -ENOSYS;
out:
	return rc;
}



int ecryptfs_free_cipher_list(struct ecryptfs_cipher_elem cipher_list_head)
{
	struct ecryptfs_cipher_elem *next;
	struct ecryptfs_cipher_elem *current = cipher_list_head.next;

	while (current) {
		next = current->next;
		free(current->kernel_name);
		free(current->user_name);
		free(current);
		current = next;
	}
	return 0;
}
