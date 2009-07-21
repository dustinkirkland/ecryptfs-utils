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

#include "config.h"
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
#include "../include/ecryptfs.h"

#define MAX_BUF_LEN 128
#define MTAB_FULLPATH "/etc/mtab"

/**
 * Pulling ourselves up by the bootstraps...
 */
int ecryptfs_get_proc_mount_point(char **proc_mount_point)
{
	FILE *fp;
	struct mntent *mntent;
	int rc = 0;

	fp = fopen(MTAB_FULLPATH, "r");
	if (!fp) {
		rc = -errno;
		goto out;
	}
	while ((mntent = getmntent(fp)))
		if (strcmp(mntent->mnt_type, "proc") == 0) {
			fclose(fp);
			if (asprintf(proc_mount_point, "%s", 
				     mntent->mnt_dir) == -1)
				rc = -ENOMEM;
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
	rc = ecryptfs_get_proc_mount_point(&proc_mount_point);
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
	rc = 0;
	if (!(crypto_file = fopen(crypto_full_path, "r"))) {
		syslog(LOG_WARNING, "%s: Failed to open [%s] for reading; This "
		       "is not a problem if the Kernel Crypto API is built as "
		       "a kernel module (called crypto_algapi) and is not "
		       "loaded. If this is not the case, eCryptfs will not be "
		       "able to use ciphers that are directly built into the "
		       "kernel.\n", __FUNCTION__, crypto_full_path);
		rc = 0;
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

static struct cipher_name_module_map {
	char *name;
	char *module;
	uint32_t blocksize;
	uint32_t min_keysize;
	uint32_t max_keysize;
	uint32_t priority;
	uint32_t enabled;
} cipher_name_module_map[] = {
	{"aes", "aes.ko", 16, 16, 32, 1, 1},
	{"aes", "aes_generic.ko", 16, 16, 32, 1, 1},
	{"serpent", "serpent.ko", 16, 0, 32, 12, 0},
	{"tnepres", "serpent.ko", 16, 0, 32, 13, 0},
	{"tea", "tea.ko", 8, 16, 16, 7, 0},
	{"xeta", "tea.ko", 8, 16, 16, 9, 0},
	{"xtea", "tea.ko", 8, 16, 16, 8, 0},
	{"blowfish", "blowfish.ko", 16, 16, 56, 2, 1},
	{"twofish", "twofish.ko", 16, 16, 32, 4, 1},
	{"khazad", "khazad.ko", 8, 16, 16, 11, 0},
	{"cast5", "cast5.ko", 8, 5, 16, 14, 1},
	{"cast6", "cast6.ko", 16, 16, 32, 5, 1},
	{"des3_ede", "des.ko", 8, 24, 24, 3, 1},
	{"des3_ede", "des_generic.ko", 8, 24, 24, 3, 1},
	{"des3_ede128", "des_s390.ko", 8, 16, 16, 14, 0},
	{"anubis", "anubis.ko", 16, 16, 40, 10, 0},
	{"cipher_null", "cipher_null.ko", 1, 0, 0, 99, 0},
	{NULL, NULL, 0, 0, 0, 0}
};

int ecryptfs_get_kernel_ciphers(struct cipher_descriptor *cd_head)
{
	struct cipher_descriptor *cd_cursor = cd_head;
	char *proc_mount_point = NULL;
	char *crypto_full_path = NULL;
	FILE *crypto_file = NULL;
	char buf[MAX_BUF_LEN];
	char *tmp = NULL;
	int rc;

	rc = ecryptfs_get_proc_mount_point(&proc_mount_point);
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
		syslog(LOG_WARNING, "%s: Failed to open [%s] for reading; This "
		       "is not a problem if the Kernel Crypto API is built as "
		       "a kernel module (called crypto_algapi) and is not "
		       "loaded. If this is not the case, eCryptfs will not be "
		       "able to use ciphers that are directly built into the "
		       "kernel.\n", __FUNCTION__, crypto_full_path);
		rc = 0;
		goto out;
	}
	while (fgets(buf, MAX_BUF_LEN, crypto_file)) {
		if (!strncmp(buf, "name", 4)) {
			struct cipher_descriptor *cd_tmp;
			int found_duplicate = 0;
			int reject, unknown;
			int i;

			strtok(buf, ": ");
			tmp = strtok(NULL, ": ");
			if (strlen(tmp) <= 0) {
				rc = -EINVAL;
				goto out;
			}
			tmp[strlen(tmp) - 1] = '\0';
			if (strncmp(tmp, "ecb", 3) == 0
			    || strncmp(tmp, "cbc", 3) == 0)
				continue;
			i = 0;
			reject = 0;
			unknown = 1;
			while (cipher_name_module_map[i].name) {
				if (!strcmp(tmp,
					     cipher_name_module_map[i].name)) {
					if (!cipher_name_module_map[i].enabled)
						reject = 1;
					unknown = 0;
					break;
				}
				i++;
			}
			if (reject || unknown)
				continue;
			cd_tmp = cd_head->next;
			while (cd_tmp) {
				if (!strcmp(cd_tmp->crypto_api_name, tmp)) {
					found_duplicate = 1;
					break;
				}
				cd_tmp = cd_tmp->next;
			}
			if (found_duplicate)
				continue;
			cd_cursor->next = malloc(sizeof(*cd_cursor));
			if (!cd_cursor->next) {
				rc = -ENOMEM;
				goto out;
			}
			memset(cd_cursor->next, 0, sizeof(*cd_cursor));
			cd_cursor->next->flags |= CIPHER_DESCRIPTOR_FLAG_LOADED;
			rc = asprintf(&cd_cursor->next->crypto_api_name,
				      "%s", tmp);
			if (rc == -1) {
				cd_cursor->next->crypto_api_name = NULL;
				free(cd_cursor->next);
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "%s: Adding kernel cipher "
				       "with name [%s] to the list\n",
				       __FUNCTION__,
				       cd_cursor->next->crypto_api_name);
		} else if (!strncmp(buf, "module", 6)) {
			if (!cd_cursor->next)
				continue;
			strtok(buf, ": ");
			tmp = strtok(NULL, ": ");
			if (strlen(tmp) <= 0) {
				rc = -EINVAL;
				goto out;
			}
			tmp[strlen(tmp) - 1] = '\0';
			rc = asprintf(&cd_cursor->next->module_name, "%s.ko",
				      tmp);
			if (rc == -1) {
				cd_cursor->next->module_name = NULL;
				free(cd_cursor->next->crypto_api_name);
				free(cd_cursor->next);
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
		} else if (!strncmp(buf, "driver", 6)) {
			if (!cd_cursor->next)
				continue;
			strtok(buf, ": ");
			tmp = strtok(NULL, ": ");
			if (strlen(tmp) <= 0) {
				rc = -EINVAL;
				goto out;
			}
			tmp[strlen(tmp) - 1] = '\0';
			rc = asprintf(&cd_cursor->next->driver_name, "%s", tmp);
			if (rc == -1) {
				cd_cursor->next->module_name = NULL;
				free(cd_cursor->next->module_name);
				free(cd_cursor->next->crypto_api_name);
				free(cd_cursor->next);
				rc = -ENOMEM;
				goto out;
			}
			rc = 0;
		} else if (!strncmp(buf, "type", 4)) {
			if (!cd_cursor->next)
				continue;
			strtok(buf, ": ");
			tmp = strtok(NULL, ": ");
			if (strlen(tmp) <= 0) {
				rc = -EINVAL;
				goto out;
			}
			tmp[strlen(tmp) - 1] = '\0';
			/* We only care about ciphers, not hashes, etc. */
			if (strncmp(tmp, "cipher", 6)) {
				free(cd_cursor->next->module_name);
				free(cd_cursor->next->crypto_api_name);
				free(cd_cursor->next->driver_name);
				free(cd_cursor->next);
				cd_cursor->next = NULL;
				continue;
			}
		} else if (!strncmp(buf, "blocksize", 9)) {
			if (!cd_cursor->next)
				continue;
			strtok(buf, ": ");
			tmp = strtok(NULL, ": ");
			if (strlen(tmp) <= 0) {
				rc = -EINVAL;
				goto out;
			}
			tmp[strlen(tmp) - 1] = '\0';
			cd_cursor->next->blocksize = atoi(tmp);
		} else if (!strncmp(buf, "min keysize", 11)) {
			int i;
			int buflen;

			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "%s: min keysize match on "
				       "buf = [%s]\n", __FUNCTION__, buf);
			if (!cd_cursor->next)
				continue;
			buflen = strlen(buf);
			i = 0;
			while (buf[i] != ':' && (i + 1) < buflen)
				i++;
			if ((i + 1) == buflen)
				continue;
			tmp = &buf[i + 2];
			tmp[strlen(tmp) - 1] = '\0';
			cd_cursor->next->min_keysize = atoi(tmp);
			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "%s: For cipher "
				       "with name [%s], set min_keysize = "
				       "[%d] from str = [%s]\n", 
				       __FUNCTION__,
				       cd_cursor->next->crypto_api_name,
				       cd_cursor->next->min_keysize, tmp);
		} else if (!strncmp(buf, "max keysize", 11)) {
			int i;
			int buflen;

			if (!cd_cursor->next)
				continue;
			buflen = strlen(buf);
			i = 0;
			while (buf[i] != ':' && (i + 1) < buflen)
				i++;
			if ((i + 1) == buflen)
				continue;
			tmp = &buf[i + 2];
			tmp[strlen(tmp) - 1] = '\0';
			cd_cursor->next->max_keysize = atoi(tmp);
			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "%s: For cipher "
				       "with name [%s], set max_keysize = "
				       "[%d] from str = [%s]\n", 
				       __FUNCTION__,
				       cd_cursor->next->crypto_api_name,
				       cd_cursor->next->max_keysize, tmp);
			cd_cursor = cd_cursor->next;
		}
	}
out:
	if (crypto_file)
		fclose(crypto_file);
	free(proc_mount_point);
	free(crypto_full_path);
	return rc;
}

int ecryptfs_get_module_ciphers(struct cipher_descriptor *cd_head)
{
	struct cipher_descriptor *cd_cursor = cd_head;
	char *kernel_crypto_dir = NULL;
	struct utsname kern_info;
	DIR *dir = NULL;
	struct dirent *dir_entry;
	int rc;

	while (cd_cursor->next)
		cd_cursor = cd_cursor->next;
	rc = uname(&kern_info);
	if (rc) {
		syslog(LOG_ERR, "%s: uname returned [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	rc = asprintf(&kernel_crypto_dir, "/lib/modules/%s/kernel/crypto",
		      kern_info.release);
	if (rc == -1) {
		syslog(LOG_ERR, "%s: Error building kernel location string\n",
		       __FUNCTION__);
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	dir = opendir(kernel_crypto_dir);
	if (!dir) {
		syslog(LOG_WARNING, "%s: opendir error on [%s]. Cannot get a "
		       "list of ciphers available as modules.\n", __FUNCTION__,
			kernel_crypto_dir);
		goto out;
	}
	while ((dir_entry = readdir(dir))) {
		struct cipher_descriptor *cd_tmp;
		int found_match;
		int i;

		if (!strstr(dir_entry->d_name, ".ko"))
			continue;
		found_match = 0;
		cd_tmp = cd_head->next;
		while (cd_tmp) {
			if (!strcmp(cd_tmp->module_name, dir_entry->d_name)) {
				found_match = 1;
				break;
			}
			cd_tmp = cd_tmp->next;
		}
		if (found_match)
			continue;
		i = 0;
		while (cipher_name_module_map[i].name) {
			if (!strncmp(cipher_name_module_map[i].module,
				     dir_entry->d_name,
				     strlen(cipher_name_module_map[i].module))) {
				if (cipher_name_module_map[i].enabled == 0) {
					i++;
					continue;
				}
				cd_cursor->next = malloc(sizeof(*cd_cursor));
				if (!cd_cursor->next) {
					rc = -ENOMEM;
					goto out;
				}
				memset(cd_cursor->next, 0, sizeof(*cd_cursor));
				rc = asprintf(&cd_cursor->next->crypto_api_name,
					      "%s",
					      cipher_name_module_map[i].name);
				if (rc == -1) {
					free(cd_cursor->next);
					rc = -ENOMEM;
					goto out;
				}
				rc = asprintf(&cd_cursor->next->module_name,
					      "%s", dir_entry->d_name);
				if (rc == -1) {
					free(cd_cursor->next->crypto_api_name);
					free(cd_cursor->next);
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
				cd_cursor->next->blocksize =
					cipher_name_module_map[i].blocksize;
				cd_cursor->next->min_keysize =
					cipher_name_module_map[i].min_keysize;
				cd_cursor->next->max_keysize =
					cipher_name_module_map[i].max_keysize;
				cd_cursor = cd_cursor->next;
			}
			i++;
		}
	}
out:
	free(kernel_crypto_dir);
	if (dir)
		closedir(dir);
	return rc;
}

int ecryptfs_sort_ciphers(struct cipher_descriptor *cd_head)
{
	struct cipher_descriptor *cd_walker;
	struct cipher_descriptor *cd_cursor;
	struct cipher_descriptor *cd_prior;
	struct cipher_descriptor *cd_highest_priority;
	struct cipher_descriptor *cd_highest_priority_parent;
	int rc = 0;

	cd_walker = cd_head;
	while (cd_walker) {
		cd_prior = cd_highest_priority_parent = cd_walker;
		cd_cursor = cd_highest_priority = cd_walker->next;
		while (cd_cursor) {
			int i;
			uint32_t cd_cursor_priority = 99;
			uint32_t cd_highest_priority_priority = 99;

			i = 0;
			while (cipher_name_module_map[i].name) {
				if (strcmp(cipher_name_module_map[i].name,
					   cd_cursor->crypto_api_name) == 0) {
					cd_cursor_priority =
						cipher_name_module_map[i].priority;
				}
				i++;
			}
			i = 0;
			while (cipher_name_module_map[i].name) {
				if (strcmp(cipher_name_module_map[i].name,
					   cd_highest_priority->crypto_api_name)
				    == 0) {
					cd_highest_priority_priority =
						cipher_name_module_map[i].priority;
				}
				i++;
			}
			if (cd_cursor_priority
			    <= cd_highest_priority_priority) {
				cd_highest_priority = cd_cursor;
				cd_highest_priority_parent = cd_prior;
			}
			cd_prior = cd_cursor;
			cd_cursor = cd_cursor->next;
		}
		if (cd_highest_priority != cd_walker->next) {
			cd_highest_priority_parent->next =
				cd_highest_priority->next;
			cd_highest_priority->next = cd_walker->next;
			cd_walker->next = cd_highest_priority;
		}
		cd_walker = cd_walker->next;
	}
	cd_prior = cd_head;
	cd_cursor = cd_head->next;
	while (cd_cursor) {
		struct cipher_descriptor *cd_next = cd_cursor->next;

		while (cd_next) {
			if (strcmp(cd_cursor->crypto_api_name,
				   cd_next->crypto_api_name) == 0) {
				cd_cursor->next = cd_next->next;
			}
			cd_next = cd_next->next;
		}
		cd_cursor = cd_cursor->next;
	}
	return rc;
}
