/**
 * Copyright (C) 2007 International Business Machines
 * Author(s): Mike Halcrow <mhalcrow@us.ibm.com>
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
#include <dlfcn.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"

static struct ecryptfs_key_mod_ops *
(*builtin_get_key_mod_ops[])(void) = {
	&passphrase_get_key_mod_ops,
	NULL
};

/**
 * ecryptfs_generate_sig_from_key_data
 * @sig:
 * @key_data:
 * @key_data_len:
 */
int ecryptfs_generate_sig_from_key_data(unsigned char *sig,
					unsigned char *key_data,
					size_t key_data_len)
{
	uint32_t key_type;
	int rc = 0;

	memcpy(&key_type, key_data, sizeof(uint32_t));
	key_type = ntohl(key_type);
	switch (key_type) {
	default:
		rc = -EINVAL;
		goto out;
	};
out:
	return rc;
}

static int ecryptfs_dummy_init(char **alias)
{
	syslog(LOG_WARNING, "%s: Dummy function substituted for unimplemented "
	       "function in key module\n", __FUNCTION__);
	(*alias) = NULL;
	return 0;
}

static int ecryptfs_dummy_get_gen_key_params(struct key_mod_param **params,
					     uint32_t *num_params)
{
	if (ecryptfs_verbosity)
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	(*params) = NULL;
	(*num_params) = 0;
	return 0;
}

static int
ecryptfs_dummy_get_gen_key_subgraph_trans_node(struct transition_node **trans,
					       uint32_t version)
{
	if (ecryptfs_verbosity)
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	(*trans) = NULL;
	return 0;
}

static int
ecryptfs_dummy_get_params(struct key_mod_param **params, uint32_t *num_params)
{
	if (ecryptfs_verbosity)
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	(*params) = NULL;
	(*num_params) = 0;
	return 0;
}

static int
ecryptfs_dummy_get_param_subgraph_trans_node(struct transition_node **trans,
					     uint32_t version)
{
	if (ecryptfs_verbosity)
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	(*trans) = NULL;
	return 0;
}

static int ecryptfs_dummy_get_blob(unsigned char *blob, size_t *blob_size,
				   struct key_mod_param_val *param_vals,
				   uint32_t num_param_vals)
{
	syslog(LOG_WARNING, "%s: Dummy function substituted for unimplemented "
	       "function in key module\n", __FUNCTION__);
	(*blob_size) = 0;
	return 0;
}

static int
ecryptfs_dummy_get_key_data(unsigned char *key_data, size_t *key_data_len,
			    unsigned char *blob)
{
	if (ecryptfs_verbosity)
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	(*key_data_len) = 0;
	return 0;
}

static int
ecryptfs_dummy_get_key_sig(unsigned char *sig, unsigned char *blob)
{
	if (ecryptfs_verbosity)
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	sig[0] = '\0';
	return 0;
}

static int ecryptfs_dummy_get_key_hint(unsigned char *hint, size_t *hint_len,
				       unsigned char *blob)
{
	if (ecryptfs_verbosity)
		syslog(LOG_WARNING,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	(*hint_len) = 0;
	return 0;
}

static int
ecryptfs_dummy_encrypt(char *to, size_t *to_size, char *from, size_t from_size,
		       unsigned char *blob, int blob_type)
{
	syslog(LOG_WARNING, "%s: Dummy function substituted for unimplemented "
	       "function in key module\n", __FUNCTION__);
	(*to_size) = 0;
	return 0;
}

static int
ecryptfs_dummy_decrypt(char *to, size_t *to_size, char *from, size_t from_size,
		       unsigned char *blob, int blob_type)
{
	syslog(LOG_WARNING, "%s: Dummy function substituted for unimplemented "
	       "function in key module\n", __FUNCTION__);
	(*to_size) = 0;
	return 0;
}

static int ecryptfs_dummy_destroy(unsigned char *blob)
{
	if (ecryptfs_verbosity)		
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	return 0;
}

static int ecryptfs_dummy_finalize(void)
{
	if (ecryptfs_verbosity)		
		syslog(LOG_INFO,
		       "%s: Dummy function substituted for unimplemented "
		       "function in key module\n", __FUNCTION__);
	return 0;	
}

int ecryptfs_fill_in_dummy_ops(struct ecryptfs_key_mod_ops *key_mod_ops)
{
	if (!key_mod_ops->init)
		key_mod_ops->init = &ecryptfs_dummy_init;
	if (!key_mod_ops->get_gen_key_params)
		key_mod_ops->get_gen_key_params =
			&ecryptfs_dummy_get_gen_key_params;
	if (!key_mod_ops->get_gen_key_subgraph_trans_node)
		key_mod_ops->get_gen_key_subgraph_trans_node =
			&ecryptfs_dummy_get_gen_key_subgraph_trans_node;
	if (!key_mod_ops->get_params)
		key_mod_ops->get_params = &ecryptfs_dummy_get_params;
	if (!key_mod_ops->get_param_subgraph_trans_node)
		key_mod_ops->get_param_subgraph_trans_node =
			&ecryptfs_dummy_get_param_subgraph_trans_node;
	if (!key_mod_ops->get_blob)
		key_mod_ops->get_blob = &ecryptfs_dummy_get_blob;
	if (!key_mod_ops->get_key_data)
		key_mod_ops->get_key_data = &ecryptfs_dummy_get_key_data;
	if (!key_mod_ops->get_key_sig)
		key_mod_ops->get_key_sig = &ecryptfs_dummy_get_key_sig;
	if (!key_mod_ops->get_key_hint)
		key_mod_ops->get_key_hint = &ecryptfs_dummy_get_key_hint;
	if (!key_mod_ops->encrypt)
		key_mod_ops->encrypt = &ecryptfs_dummy_encrypt;
	if (!key_mod_ops->decrypt)
		key_mod_ops->decrypt = &ecryptfs_dummy_decrypt;
	if (!key_mod_ops->destroy)
		key_mod_ops->destroy = &ecryptfs_dummy_destroy;
	if (!key_mod_ops->finalize)
		key_mod_ops->finalize = &ecryptfs_dummy_finalize;
	return 0;
}

/**
 * Called from: src/libecryptfs/module_mgr.c::ecryptfs_process_decision_graph
 */
int ecryptfs_register_key_modules(struct ecryptfs_ctx* ctx)
{
	DIR *dp = NULL;
	struct dirent *ep;
	char *dir_name = NULL;
	int i;
	struct ecryptfs_key_mod *curr_key_mod = &(ctx->key_mod_list_head);
	struct ecryptfs_key_mod_ops *(*walker)(void);
	int rc = 0;

	if (asprintf(&dir_name, "%s", ECRYPTFS_DEFAULT_KEY_MOD_DIR) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	if (!(dp = opendir(dir_name))) {
		syslog(LOG_WARNING,
		       "ERROR: Could not open key_mod directory\n");
		rc = -EPERM;
		goto out;
	}
	while ((ep = readdir(dp))) {
		struct ecryptfs_key_mod *new_key_mod = NULL;
		size_t dir_length;
		char *path = NULL;
		char *key_mod_dir = ECRYPTFS_DEFAULT_KEY_MOD_DIR;
		void *handle;
		struct ecryptfs_key_mod_ops *(*get_key_mod_ops)(void);

		/* Check if file ends with .so */
		dir_length = strlen(ep->d_name);
		if ((dir_length < 3)
		    || strcmp((ep->d_name + (dir_length - 3)), ".so"))
			continue;
		if (asprintf(&path, "%s/%s", key_mod_dir, ep->d_name) == -1) {
			syslog(LOG_ERR, "Out of memory\n");
			rc = -ENOMEM;
			goto out;
		}
		rc = 0;
		handle = dlopen(path, RTLD_LAZY);
		if (!handle) {
			syslog(LOG_ERR, "Could not open library handle\n");
			goto end_loop;
		}
		get_key_mod_ops = (struct ecryptfs_key_mod_ops *(*)(void))
			dlsym(handle, "get_key_mod_ops");
		if (!get_key_mod_ops) {
			syslog (LOG_ERR, "Error attempting to get the symbol "
				"[get_key_mod_ops] from key module [%s]: "
				"err = [%s]. The key module is likely using "
				"the deprecated key module API.\n", path,
				dlerror());
			goto end_loop;
		}
		new_key_mod = malloc(sizeof(struct ecryptfs_key_mod));
		if (!new_key_mod) {
			syslog(LOG_ERR, "Out of memory\n");
			free(path);
			rc = -ENOMEM;
			goto out;
		}
		memset(new_key_mod, 0, sizeof(struct ecryptfs_key_mod));
		new_key_mod->ops = (get_key_mod_ops)();
		if (!new_key_mod->ops) {
			syslog (LOG_ERR, "Library function get_key_mod_ops() "
				"failed to return ops for [%s]\n", path);
			free(new_key_mod);
			rc = 0;
			goto end_loop;
		}
		if ((rc = ecryptfs_fill_in_dummy_ops(new_key_mod->ops))) {
			syslog (LOG_ERR, "Error attempting to fill in missing  "
				"key module operations for [%s]; rc = [%d]\n",
				path, rc);
			free(new_key_mod);
			rc = 0;
			goto end_loop;			
		}
		if ((rc = new_key_mod->ops->init(&new_key_mod->alias))) {
			syslog(LOG_ERR, "Error initializing key module [%s]; "
			       "rc = [%d]\n", path, rc);
			free(new_key_mod);
			rc = 0;
			goto end_loop;
		}
		new_key_mod->lib_handle = handle;
		new_key_mod->lib_path = path;
		curr_key_mod->next = new_key_mod;
		curr_key_mod = new_key_mod;
		continue;
	end_loop:
		free(path);
	}
	closedir(dp);
	i = 0;
	walker = builtin_get_key_mod_ops[i];
	while (walker) {
		struct ecryptfs_key_mod *new_key_mod;
		struct ecryptfs_key_mod *tmp_key_mod;

		if (!(new_key_mod = malloc(sizeof(struct ecryptfs_key_mod)))) {
			syslog(LOG_ERR, "Out of memory\n");
			rc = -ENOMEM;
			goto out;
		}
		memset(new_key_mod, 0, sizeof(struct ecryptfs_key_mod));
		new_key_mod->ops = (walker)();
		if (!new_key_mod->ops) {
			syslog (LOG_ERR, "Library function get_key_mod_ops() "
				"failed to return ops for built-in key "
				"module in array position [%d]\n", i);
			free(new_key_mod);
			rc = 0;
			goto end_loop_2;
		}
		if ((rc = new_key_mod->ops->init(&new_key_mod->alias))) {
			syslog(LOG_ERR, "Error initializing key module in "
			       "array position [%d]\n", i);
			free(new_key_mod);
			rc = 0;
			goto end_loop_2;
		}
		tmp_key_mod = ctx->key_mod_list_head.next;
		while (tmp_key_mod) {
			if (strcmp(tmp_key_mod->alias, new_key_mod->alias)
			    == 0) {
				free(new_key_mod->alias);
				free(new_key_mod);
				if (ecryptfs_verbosity)
					syslog(LOG_INFO,
					       "Preferring [%s] file over "
					       "built-in module for key module "
					       "with name [%s]\n",
					       tmp_key_mod->lib_path,
					       tmp_key_mod->alias);
				goto end_loop_2;
			}
			tmp_key_mod = tmp_key_mod->next;
		}
		curr_key_mod->next = new_key_mod;
		curr_key_mod = new_key_mod;
end_loop_2:
		i++;
		walker = builtin_get_key_mod_ops[i];
	}
out:
	free(dir_name);
	return rc;
}

/**
 * ecryptfs_find_key_mod
 *
 * Get the key_mod struct for the given alias.
 */
int ecryptfs_find_key_mod(struct ecryptfs_key_mod **key_mod,
			  struct ecryptfs_ctx *ctx, char *key_mod_alias)
{
	struct ecryptfs_key_mod *curr;
	int rc = 0;

	curr = ctx->key_mod_list_head.next;
	while (curr) {
		if (!strncmp(curr->alias, key_mod_alias,
			     strlen(curr->alias))) {
			*key_mod = curr;
			goto out;
		}
		curr = curr->next;
	}
	rc = 1;
out:
	return rc;
}

int ecryptfs_free_key_mod_list(struct ecryptfs_ctx *ctx)
{
	struct ecryptfs_key_mod *curr = ctx->key_mod_list_head.next;
	struct ecryptfs_key_mod *temp;

	while (curr) {
		curr->ops->finalize();
		dlclose (curr->lib_handle);
		free(curr->lib_path);
		temp = curr;
		curr = curr->next;
		free(temp);
	}
	ctx->key_mod_list_head.next = NULL;
	return 0;
}
