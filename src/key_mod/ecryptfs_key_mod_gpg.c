/**
 * Copyright (C) 2007 International Business Machines Corp.
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
#include <fcntl.h>
#include <pwd.h>
#include <stdio.h>
#include <string.h>
#include <syslog.h>
#include <errno.h>
#include <stdlib.h>
#include <unistd.h>
#include <gpgme.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"

struct key_mod_gpg {
#define KEY_MOD_DATA_SET 0x00000001
	uint32_t flags;
	gpgme_ctx_t ctx;
	unsigned int keylist_idx;
	char *gpgsig;
	char *sig;
};

void destroy_key_mod_gpg(struct key_mod_gpg *key_mod_gpg)
{
	if (key_mod_gpg->sig)
		free(key_mod_gpg->sig);
	memset(key_mod_gpg, 0, sizeof(struct key_mod_gpg));
}

static int serialize_key_module_data(unsigned char *blob,
				     struct key_mod_gpg *key_mod_data)
{
	int rc = 0;

out:
	return rc;
}

static int deserialize_key_module_data(struct key_mod_gpg *key_mod_data,
				       unsigned char *blob)
{
	int rc = 0;

out:
	return rc;
}

static int
ecryptfs_gpg_initialize_key_module_state(unsigned char *blob,
					 struct ecryptfs_name_val_pair *pair)
			    
{
	struct key_mod_gpg key_mod_gpg;	
	char *gpgsig = NULL;
	unsigned int gpgsig_len;
	int i = 0;
	int rc = 0;

	while (pair) {
		if (!pair->name)
			;
		else if (!strcmp(pair->name, "gpgsig"))
			gpgsig = pair->value;
		pair = pair->next;
	}
	if (gpgsig) {
		gpgsig_len = strlen(gpgsig) + 1;
		blob[i++] = gpgsig_len % 256;
		blob[i++] = gpgsig_len >> 8;
		memcpy(&blob[i], gpgsig, gpgsig_len);
		i += gpgsig_len;
	} else {
		rc = -EINVAL;
		goto out;
	}
	/* TODO: Get the gpg key */
	key_mod_gpg.flags = KEY_MOD_DATA_SET;
	serialize_key_module_data(blob, &key_mod_gpg);
out:
	return rc;
}

static int
ecryptfs_gpg_get_key_metadata(char *sig, int *length, unsigned char *blob)
{
	struct key_mod_gpg key_mod_gpg;
	int rc = 0;

	sig[0] = '\0';
	(*length) = 0;
	memset(&key_mod_gpg, 0, sizeof(struct key_mod_gpg));
	if ((rc = deserialize_key_module_data(&key_mod_gpg, blob))) {
		goto out;
	}
	memcpy(sig, key_mod_gpg.sig, ECRYPTFS_SIG_SIZE_HEX + 1);
	(*length) = 0; /* TODO */
out:
	destroy_key_mod_gpg(&key_mod_gpg);
	return rc;
}

int ecryptfs_gpg_generate_key(char *filename)
{
	int rc = 0;

out:
	return rc;
}

int ecryptfs_gpg_encrypt(char *to, int size, char *from, unsigned char *blob)
{
	int rc = 0;

/*	gpg_op_encrypt(...); */
out:
	return rc;
}

int ecryptfs_gpg_decrypt(char *to, size_t *decrypted_key_size, char *from, 
			 unsigned char *blob)
{
/*	gpgme_key_t key;
	int rc;

.	gpgme_get_key(ctx, &key);
	if (rc) {
		rc = -(int)ERR_get_error();
		syslog(LOG_ERR, "Error attempting to read RSA key from file;"
		       " rc = [%d]\n", rc);
		goto out;
	}
	gpgme_decrypt(...);
	if (rc == -1) {
		rc = -(int)ERR_get_error();
		syslog(LOG_ERR, "Error attempting to perform RSA public key "
		       "decryption; rc = [%d]\n", rc);
	} else {
		*decrypted_key_size = rc;
		rc = 0;
	}
out:
.	free? */
	return 0;
}

struct pki_nvp_map_elem {
	char *name;
	uint32_t flags;
};

static struct pki_nvp_map_elem pki_nvp_map[] = {
	{"gpgsig", (ECRYPTFS_PARAM_FLAG_ECHO_INPUT
		    | ECRYPTFS_DEFAULT_VALUE_SET)},
	{NULL, 0}
};

/*

static int ssl_sig(struct ecryptfs_pki_elem *pki, struct val_node **head)
{
	struct ecryptfs_name_val_pair *openssl_nvp;
	char *sig;
	char *param;
	int rc;

	sig = malloc(ECRYPTFS_SIG_SIZE_HEX + 1);
	if (!sig) {
		rc = -ENOMEM;
		goto out;
	}
	rc = ecryptfs_add_key_module_key_to_keyring(sig, pki);
	if (rc < 0)
		goto out;
	else
		rc = 0;
	asprintf(&param, "ecryptfs_sig=%s", sig);
	free(sig);
	stack_push(head, param);
out:
	if (rc)
		return MOUNT_ERROR;
	return DEFAULT_TOK;
}

static int tf_ssl_file(struct ecryptfs_ctx *ctx, struct param_node *node,
		       struct val_node **head, void **foo)
{
	stack_push(head, node->val);
	node->val = NULL;
	return DEFAULT_TOK;
}

*/

static int tf_gpg_keysig(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **head, void **foo);

/* TODO: Create a param node for each block of keysigs in the gpg
 * keyring. Make one option point to the previous node and another to
 * the next node. */

#define GPG_TOK 0
static struct param_node gpg_param_nodes[] = {
	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"keysig"},
	 .prompt = "Key signature",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_NO_VALUE,
	 .num_transitions = 1,
	 .tl = {{.flags = 0,
		 .val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_gpg_keysig}}},
};

/**
 * tf_gpg_keysig
 * @ctx: 
 * @node: 
 * @head: The value node list for this key module
 * @foo: 
 *
 */
static int tf_gpg_keysig(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **head, void **foo)
{
	struct key_mod_gpg *key_mod_gpg = (struct key_mod_gpg *)(*foo);
	int i = 0;
	gpgme_error_t err;
	int rc = 0;
	gpgme_key_t key;

	while ((err = gpgme_op_keylist_next(key_mod_gpg->ctx, &key)) == 0) {
		gpgme_subkey_t subkey = key->subkeys;

		while (subkey) {
			if ((rc = asprintf(&gpg_param_nodes[0].tl[i].val,
					   "%s", subkey->keyid)) == -1) {
				rc = -ENOMEM;
				goto out;
			}
			subkey = subkey->next;
		}
	}
	rc = 0;
out:
	return rc;
}

int validate_keysig(char *keysig)
{
	int rc = 0;

out:
	return rc;
}

static int generate_name_val_list(struct ecryptfs_name_val_pair *head)
{
	uid_t id = getuid();
	int rc = 0;

	head->next = NULL;
out:
	return rc;
}

static int tf_gpg_exit(struct ecryptfs_ctx *ctx, struct param_node *node,
		       struct val_node **head, void **foo)
{
	struct key_mod_gpg *key_mod_gpg;

	key_mod_gpg = (struct key_mod_gpg *)(*foo);
	if (key_mod_gpg) {
		destroy_key_mod_gpg(key_mod_gpg);
		free(key_mod_gpg);
	}
	return 0;
}


static int tf_gpg_enter(struct ecryptfs_ctx *ctx, struct param_node *node,
			    struct val_node **head, void **foo)
{
	struct key_mod_gpg *key_mod_gpg;
	gpgme_error_t err;
	int rc = 0;

	(*foo) = NULL;
	if ((key_mod_gpg = malloc(sizeof(struct key_mod_gpg))) == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	if ((err = gpgme_new(&key_mod_gpg->ctx))) {
		printf("Error attempting to initialize new GPGME ctx\n");
		rc = -EINVAL;
		free(key_mod_gpg);
		goto out;
	}
	if ((err = gpgme_op_keylist_start(key_mod_gpg->ctx, "", 0))) {
		printf("Error attempting to start keylist\n");
		rc = -EINVAL;
		gpgme_release(key_mod_gpg->ctx);
		free(key_mod_gpg);
		goto out;
	}
	key_mod_gpg->keylist_idx = 0;
	(*foo) = (void *)key_mod_gpg;
out:
	return rc;
}

struct transition_node gpg_transition = {
	.val = "gpg",
	.pretty_val = "GnuPG Module",
	.next_token = &(gpg_param_nodes[0]),
	.trans_func = tf_gpg_enter
};

static int
ecryptfs_gpg_get_param_subgraph_trans_node(struct transition_node **trans,
					   uint32_t version)
{
	if ((version & ECRYPTFS_VERSIONING_PUBKEY) == 0)
		return -1;
	*trans = &gpg_transition;
	return 0;
}

int destruct_pki(void)
{
	return 0;
}

int fill_in_sig_transitions(void)
{
	int rc = 0;

/*	gpg_param_nodes[0].tl */
out:
	return rc;
}

static int ecryptfs_gpg_init(char **alias)
{
	uid_t id;
	struct passwd *pw;
	int rc = 0;

	if (asprintf(alias, "gpgme") == -1) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Out of memory\n");
		goto out;
	}
	id = getuid();
	pw = getpwuid(id);
	rc = -EINVAL; /* Disable for now */
out:
	return rc;
}

int ecryptfs_gpg_finalize(void)
{
	return 0;
}

static struct ecryptfs_key_mod_ops ecryptfs_gpg_ops = {
	&ecryptfs_gpg_init,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	NULL,
	&ecryptfs_gpg_finalize
};

struct ecryptfs_key_mod_ops *get_key_mod_ops(void)
{
	return &ecryptfs_gpg_ops;
}
