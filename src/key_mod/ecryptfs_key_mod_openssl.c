/**
 * Copyright (C) 2006-2007 International Business Machines Corp.
 * Author(s): Trevor S. Highland <trevor.highland@gmail.com>
 *            Mike Halcrow <mhalcrow@us.ibm.com>
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
 *
 * In addition, as a special exception, the copyright holders give
 * permission to link the code of portions of this program with the
 * OpenSSL library under certain conditions as described in each
 * individual source file, and distribute linked combinations
 * including the two.
 * You must obey the GNU General Public License in all respects
 * for all of the code used other than OpenSSL.  If you modify
 * file(s) with this exception, you may extend this exception to your
 * version of the file(s), but you are not obligated to do so.  If you
 * do not wish to do so, delete this exception statement from your
 * version.  If you delete this exception statement from all source
 * files in the program, then also delete it here.
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
#include <libgen.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/err.h>
#include <openssl/engine.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"

struct openssl_data {
	char *path;
	char *passphrase;
};

static void
ecryptfs_openssl_destroy_openssl_data(struct openssl_data *openssl_data)
{
	free(openssl_data->path);
	free(openssl_data->passphrase);
	memset(openssl_data, 0, sizeof(struct openssl_data));
}

/**
 * ecryptfs_openssl_deserialize
 * @openssl_data: The deserialized version of the key module data;
 *                internal components pointed to blob memory
 * @blob: The key module-specific state blob
 *
 */
static int ecryptfs_openssl_deserialize(struct openssl_data *openssl_data,
					unsigned char *blob)
{
	size_t path_length;
	size_t passphrase_length;
	size_t i = 0;

	path_length = blob[i++] % 256;
	path_length += blob[i++] << 8;
	i += path_length;
	passphrase_length = blob[i++] % 256;
	passphrase_length += blob[i++] << 8;
	openssl_data->path = (char *) blob + 2;
	openssl_data->passphrase = (openssl_data->path + path_length + 2);
	return 0;
}

/**
 * @blob: Callee allocates this memory
 */
static int ecryptfs_openssl_serialize(unsigned char *blob, size_t *blob_size,
				      struct openssl_data *openssl_data)
{
	size_t path_length;
	size_t passphrase_length;
	size_t i = 0;
	int rc = 0;

	(*blob_size) = 0;
	if (!openssl_data->path || !openssl_data->passphrase) {
		rc = -EINVAL;
		syslog(LOG_ERR, "openssl_data internal structure not "
		       "properly filled in\n");
		goto out;
	}
	path_length = strlen(openssl_data->path) + 1; /* + '\0' */
	passphrase_length = strlen(openssl_data->passphrase) + 1;
	(*blob_size) = (2 + path_length + 2 + passphrase_length);
	if (!blob)
		goto out;
	blob[i++] = path_length % 256;
	blob[i++] = path_length >> 8;
	memcpy(&blob[i], openssl_data->path, path_length);
	i += path_length;
	blob[i++] = passphrase_length % 256;
	blob[i++] = passphrase_length >> 8;
	memcpy(&blob[i], openssl_data->passphrase, passphrase_length);
out:
	return rc;
}

struct ecryptfs_subgraph_ctx {
	struct ecryptfs_key_mod *key_mod;
	struct openssl_data openssl_data;
};

static void
ecryptfs_openssl_destroy_subgraph_ctx(struct ecryptfs_subgraph_ctx *ctx)
{
	ecryptfs_openssl_destroy_openssl_data(&ctx->openssl_data);
	memset(ctx, 0, sizeof(struct ecryptfs_subgraph_ctx));
}

/**
 * ecryptfs_openssl_generate_signature
 * @sig: Generated sig (ECRYPTFS_SIG_SIZE_HEX + 1 bytes of allocated memory)
 * @key: RSA key from which to generate sig
 */
static int ecryptfs_openssl_generate_signature(char *sig, RSA *key)
{
	int len, nbits, ebits, i;
	int nbytes, ebytes;
	unsigned char *hash;
	unsigned char *data = NULL;
	int rc = 0;

	hash = malloc(SHA_DIGEST_LENGTH);
	if (!hash) {
		syslog(LOG_ERR, "Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	nbits = BN_num_bits(key->n);
	nbytes = nbits / 8;
	if (nbits % 8)
		nbytes++;
	ebits = BN_num_bits(key->e);
	ebytes = ebits / 8;
	if (ebits % 8)
		ebytes++;
	len = 10 + nbytes + ebytes;
	data = malloc(3 + len);
	if (!data) {
		syslog(LOG_ERR, "Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	i = 0;
	data[i++] = '\x99';
	data[i++] = (len >> 8);
	data[i++] = len;
	data[i++] = '\x04';
	data[i++] = '\00';
	data[i++] = '\00';
	data[i++] = '\00';
	data[i++] = '\00';
	data[i++] = '\02';
	data[i++] = (nbits >> 8);
	data[i++] = nbits;
	BN_bn2bin(key->n, &(data[i]));
	i += nbytes;
	data[i++] = (ebits >> 8);
	data[i++] = ebits;
	BN_bn2bin(key->e, &(data[i]));
	i += ebytes;
	SHA1(data, len + 3, hash);
	to_hex(sig, (char *)hash, ECRYPTFS_SIG_SIZE);
	sig[ECRYPTFS_SIG_SIZE_HEX] = '\0';
out:
	free(data);
	free(hash);
	return rc;
}

static int
ecryptfs_openssl_mkdir_recursive(char *dir, mode_t mode)
{
	char *temp = NULL;
	char *parent = NULL;
	int rc = 0;

	if (!strcmp(dir, ".") || !strcmp(dir, "/"))
		goto out;
	temp = strdup(dir);
	if (temp == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	parent = dirname(temp);
	rc = ecryptfs_openssl_mkdir_recursive(parent, mode);
	if (rc)
		goto out;
	if (mkdir(dir, mode) == -1) {
		if (errno != EEXIST) {
			rc = -errno;
			goto out;
		}
	}
	rc = 0;
out:
	free(temp);
	return rc;
}

static int
ecryptfs_openssl_write_key_to_file(RSA *rsa, char *filename, char *passphrase)
{
	char *tmp_filename;
	char *openssl_dir;
	BIO *out;
	const EVP_CIPHER *enc = EVP_aes_256_cbc();
	int rc = 0;

	tmp_filename = strdup(filename);
	if (tmp_filename == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	openssl_dir = dirname(tmp_filename);
	rc = ecryptfs_openssl_mkdir_recursive(openssl_dir, 0700);
	if (rc) {
		syslog(LOG_WARNING, "%s: Error attempting to mkdir [%s]; "
		       "rc = [%d]\n", __FUNCTION__, openssl_dir, rc);
	}
	if ((out = BIO_new(BIO_s_file())) == NULL) {
		syslog(LOG_ERR, "Unable to create BIO for output\n");
		rc= -EIO;
		goto out;
	}
	if (BIO_write_filename(out, filename) <= 0) {
		syslog(LOG_ERR, "Failed to open file for reading\n");
		rc = -EIO;
		goto out_free_bio;
	}
	if (!PEM_write_bio_RSAPrivateKey(out, rsa, enc, NULL, 0, NULL,
					 (void *)passphrase)) {
		syslog(LOG_ERR, "Failed to write key to file\n");
		rc = -EIO;
		goto out_free_bio;
	}
out_free_bio:
	BIO_free_all(out);
out:
	free(tmp_filename);
	return rc;
}

/**
 * ecryptfs_openssl_read_key
 * @rsa: RSA key to allocate
 * @blob: Key module data to use in finding the key
 */
static int ecryptfs_openssl_read_key(RSA **rsa, unsigned char *blob)
{
	struct openssl_data *openssl_data = NULL;
	BIO *in = NULL;
	int rc;

	CRYPTO_malloc_init();
	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	ENGINE_load_builtin_engines();
	openssl_data = malloc(sizeof(struct openssl_data));
	if (!openssl_data) {
		syslog(LOG_ERR, "Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	ecryptfs_openssl_deserialize(openssl_data, blob);
	if ((in = BIO_new(BIO_s_file())) == NULL) {
		syslog(LOG_ERR, "Unable to create BIO for output\n");
		rc = -EIO;
		goto out;
	}
	if (BIO_read_filename(in, openssl_data->path) <= 0) {
		syslog(LOG_ERR, "Unable to read filename [%s]\n",
		       openssl_data->path);
		rc = -EIO;
		goto out;
	}
	if ((*rsa = PEM_read_bio_RSAPrivateKey(in, NULL, NULL,
					       openssl_data->passphrase))
	    == NULL) {
		syslog(LOG_ERR,
		       "%s: Unable to read private key from file [%s]\n",
		       __FUNCTION__, openssl_data->path);
		rc = -ENOKEY;
		goto out;
	}
	rc = 0;
out:
	free(openssl_data);
	BIO_free_all(in);
	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_remove_state(0);
	ERR_free_strings();
	return rc;
}

int ecryptfs_openssl_get_key_sig(unsigned char *sig, unsigned char *blob)
{
	RSA *rsa = NULL;
	int rc;

	if ((rc = ecryptfs_openssl_read_key(&rsa, blob))) {
		syslog(LOG_ERR, "Error attempting to read RSA key from file;"
		       " rc = [%d]\n", rc);
		goto out;
	}
	if ((rc = ecryptfs_openssl_generate_signature((char *)sig, rsa))) {
		syslog(LOG_ERR, "%s: Error attempting to generate key "
		       "signature; rc = [%d]\n", __FUNCTION__, rc);
		goto out_free_rsa;
	}
out_free_rsa:
	RSA_free(rsa);
out:
	return rc;
}

/**
 * ecryptfs_openssl_generate_key
 * @filename: File into which to write the newly generated key
 *
 * Generate a new key and write it out to a file.
 */
static int ecryptfs_openssl_generate_key(struct openssl_data *openssl_data)
{
	RSA *rsa;
	int rc = 0;

	if ((rsa = RSA_generate_key(1024, 65537, NULL, NULL)) == NULL) {
		syslog(LOG_ERR, "Error generating new RSA key\n");
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = ecryptfs_openssl_write_key_to_file(
		     rsa, openssl_data->path, openssl_data->passphrase))) {
		syslog(LOG_ERR, "Error writing key to file; rc = [%d]\n", rc);
		rc = -EIO;
		goto out_free_rsa;
	}
out_free_rsa:
	RSA_free(rsa);
out:
	return rc;
}

/**
 * ecryptfs_openssl_encrypt
 * @to: Where to write encrypted data
 * @size: Number of bytes to encrypt
 * @from: Data to encrypt
 * @blob: Arbitrary blob specific to this key module
 *
 * Encrypt @size bytes of data in @from, writing the encrypted data
 * into @to, using @blob as the parameters for the
 * encryption.
 */
static int ecryptfs_openssl_encrypt(char *to, size_t *to_size, char *from,
				    size_t from_size, unsigned char *blob,
				    int blob_type)
{
	RSA *rsa = NULL;
	int rc;

	(*to_size) = 0;
	if ((rc = ecryptfs_openssl_read_key(&rsa, blob))) {
		rc = -(int)ERR_get_error();
		syslog(LOG_ERR, "Error attempting to read RSA key from file;"
		       " rc = [%d]\n", rc);
		goto out;
	}
	(*to_size) = RSA_size(rsa);
	if (to) {
		if ((rc = RSA_public_encrypt(from_size, (unsigned char *)from,
					     (unsigned char *)to, rsa,
					     RSA_PKCS1_OAEP_PADDING)) == -1) {
			rc = -(int)ERR_get_error();
			syslog(LOG_ERR, "Error attempting to perform RSA "
			       "public key encryption; rc = [%d]\n", rc);
			goto out_free_rsa;
		} else {
			(*to_size) = rc;
			rc = 0;
		}
	}
out_free_rsa:
	RSA_free(rsa);
out:

	return rc;
}

/**
 * ecryptfs_openssl_dencrypt
 * @from: Data to decrypt
 * @to: Where to write decrypted data
 * @decrypted_key_size: Number of bytes decrypted
 * @blob: Arbitrary blob specific to this key module
 *
 * Decrypt data in @from, writing the decrypted data into @to, using
 * @blob as the parameters for the encryption.
 */
static int ecryptfs_openssl_decrypt(char *to, size_t *to_size, char *from,
				    size_t from_size, unsigned char *blob,
				    int blob_type)
{
	RSA *rsa = NULL;
	int rc;

	(*to_size) = 0;
	if ((rc = ecryptfs_openssl_read_key(&rsa, blob))) {
		rc = -(int)ERR_get_error();
		syslog(LOG_ERR, "Error attempting to read RSA key from file;"
		       " rc = [%d]\n", rc);
		goto out;
	}
	(*to_size) = RSA_size(rsa);
	if (to) {
		if ((rc = RSA_private_decrypt(from_size, (unsigned char *)from,
					      (unsigned char *)to, rsa,
					      RSA_PKCS1_OAEP_PADDING)) == -1) {
			rc = -(int)ERR_get_error();
			syslog(LOG_ERR, "Error attempting to perform RSA "
			       "public key decryption; rc = [%d]\n", rc);
			goto out_free_rsa;
		} else {
			(*to_size) = rc;
			rc = 0;
		}
	}
out_free_rsa:
	RSA_free(rsa);
out:
	return rc;
}
int ecryptfs_openssl_init_from_param_vals(struct openssl_data *, struct key_mod_param_val *, uint32_t);
static int ecryptfs_openssl_get_blob(unsigned char *blob, size_t *blob_size,
				     struct key_mod_param_val *param_vals,
				     uint32_t num_param_vals)
{
	struct openssl_data openssl_data;
	int rc = 0;

	if ((rc = ecryptfs_openssl_init_from_param_vals(&openssl_data,
							param_vals,
							num_param_vals))) {
		syslog(LOG_ERR, "Error parsing parameter values; rc = [%d]\n",
		       rc);
		goto out;
	}
	if (blob == NULL) {
		if ((rc = ecryptfs_openssl_serialize(NULL, blob_size,
						     &openssl_data))) {
			syslog(LOG_ERR,
			       "Error serializing openssl; rc = [%d]\n", rc);
			goto out;
		}
		goto out;
	}
	if ((rc = ecryptfs_openssl_serialize(blob, blob_size, &openssl_data))) {
		syslog(LOG_ERR, "Error serializing openssl; rc = [%d]\n", rc);
		goto out;
	}
out:
	return rc;
}

static int tf_ssl_keyfile(struct ecryptfs_ctx *ctx, struct param_node *node,
			  struct val_node **mnt_params, void **foo)
{
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	int rc;

	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_ctx->openssl_data.path, "%s", node->val))
	    == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = DEFAULT_TOK;
	free(node->val);
	node->val = NULL;
out:
	return rc;
}

static int
ecryptfs_openssl_process_key(struct ecryptfs_subgraph_ctx *subgraph_ctx,
			     struct val_node **mnt_params)
{
	size_t blob_size;
	char *sig_mnt_opt;
	char sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	int rc;

	if ((rc = ecryptfs_openssl_serialize(NULL, &blob_size, 
					     &subgraph_ctx->openssl_data))) {
		syslog(LOG_ERR, "Error serializing openssl; rc = [%d]\n", rc);
		rc = MOUNT_ERROR;
		goto out;
	}
	if (blob_size == 0) {
		syslog(LOG_ERR, "Error serializing openssl\n");
		rc = MOUNT_ERROR;
		goto out;
	}
	if ((subgraph_ctx->key_mod->blob = malloc(blob_size)) == NULL) {
		syslog(LOG_ERR, "Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = ecryptfs_openssl_serialize((unsigned char *) 
					     subgraph_ctx->key_mod->blob,
					     &subgraph_ctx->key_mod->blob_size, 
					     &subgraph_ctx->openssl_data))) {
		syslog(LOG_ERR, "Error serializing openssl; rc = [%d]\n", rc);
		rc = MOUNT_ERROR;
		goto out;
	}
	if (subgraph_ctx->key_mod->blob_size != blob_size) {
		syslog(LOG_ERR, "%s: Internal error\n", __FUNCTION__);
		exit(1);
	}
	if ((rc = ecryptfs_add_key_module_key_to_keyring(
		     sig, subgraph_ctx->key_mod)) < 0) {
		syslog(LOG_ERR, "Error attempting to add key to keyring for "
		       "key module [%s]; rc = [%d]\n",
		       subgraph_ctx->key_mod->alias, rc);
		goto out;
	}
	if ((rc = asprintf(&sig_mnt_opt, "ecryptfs_sig=%s", sig)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = stack_push(mnt_params, sig_mnt_opt);
out:
	return rc;
}

static int limit_key_size(struct val_node **params, 
			  struct ecryptfs_subgraph_ctx *subgraph_ctx)
{
	char *buf;
	int rc;
	RSA *rsa = NULL;

	if ((rc=ecryptfs_openssl_read_key(&rsa, 
				(unsigned char *)subgraph_ctx->key_mod->blob)))
		return rc;
	/* 41 is for padding and 3 are for additional data send from 
	 * kernel (1 for cipher type and 2 for checksum */
	if ((rc = asprintf(&buf, "max_key_bytes=%d", 
			   RSA_size(rsa)-41-3)) == -1) {
		rc = -ENOMEM;
		goto out;
	}

	rc = stack_push(params, buf);
out:	
	RSA_free(rsa);
	return rc;
}

/**
 *
 * 
 */
static int tf_ssl_passwd(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	int rc;

	if (ecryptfs_verbosity)	
		syslog(LOG_INFO, "%s: Called w/ node->val = [%s]\n",
		       __FUNCTION__, node->val);
	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_ctx->openssl_data.passphrase, "%s",
			   node->val)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	free(node->val);
	node->val = NULL;
	if ((rc = ecryptfs_openssl_process_key(subgraph_ctx, mnt_params))) {
		syslog(LOG_ERR, "Error processing OpenSSL key; rc = [%d]", rc);
		goto out;
	}
	limit_key_size(mnt_params, subgraph_ctx);
	ecryptfs_openssl_destroy_subgraph_ctx(subgraph_ctx);
	free(subgraph_ctx);
	(*foo) = NULL;
	rc = DEFAULT_TOK;
out:
	return rc;
}

static int tf_ssl_passwd_file(struct ecryptfs_ctx *ctx, struct param_node *node,
			      struct val_node **mnt_params, void **foo)
{
	int rc = 0;
	int fd;
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	struct ecryptfs_name_val_pair file_head = { 0, };
	struct ecryptfs_name_val_pair *walker = NULL;

	syslog(LOG_INFO, "%s: Called\n", __FUNCTION__);
	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	if (strcmp(node->mnt_opt_names[0], "openssl_passwd_file") == 0)
		fd = open(node->val, O_RDONLY);
	else if (strcmp(node->mnt_opt_names[0], "openssl_passwd_fd") == 0)
		fd = strtol(node->val, NULL, 0);
	else {
		rc = MOUNT_ERROR;
		goto out;
	}
	if (fd == -1) {
		syslog(LOG_ERR, "%s: Error attempting to open file\n",
		       __FUNCTION__);
		rc = MOUNT_ERROR;
		goto out;
	}
	rc = parse_options_file(fd, &file_head);
	close(fd);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to parse options out "
		       "of file\n", __FUNCTION__);
		goto out;
	}
	walker = file_head.next;
	while (walker) {
		if (strcmp(walker->name, "openssl_passwd") == 0) {
			if ((rc = 
			     asprintf(&subgraph_ctx->openssl_data.passphrase,
				      "%s", walker->value)) == -1) {
				rc = -ENOMEM;
				goto out;
			}
			break;
		}
		walker = walker->next;
	}
	if (!walker) {
		syslog(LOG_ERR, "%s: No openssl_passwd option found in file\n",
		       __FUNCTION__);
		rc = MOUNT_ERROR;
		goto out;
	}
	walker = NULL;
	if ((rc = ecryptfs_openssl_process_key(subgraph_ctx, mnt_params))) {
		syslog(LOG_ERR, "Error processing OpenSSL key; rc = [%d]", rc);
		goto out;
	}
	limit_key_size(mnt_params, subgraph_ctx);
	ecryptfs_openssl_destroy_subgraph_ctx(subgraph_ctx);
	free(subgraph_ctx);
	(*foo) = NULL;
	rc = DEFAULT_TOK;
out:
	free_name_val_pairs(file_head.next);
	free(file_head.name);
	free(file_head.value);
	free(node->val);
	node->val = NULL;
	syslog(LOG_INFO, "%s: Exiting\n", __FUNCTION__);
	return rc;
}

static int tf_ssl_passwd_fd(struct ecryptfs_ctx *ctx, struct param_node *node,
			    struct val_node **mnt_params, void **foo)
{
	return ENOSYS;
}

static int tf_ecryptfs_openssl_gen_key_param_node_keyfile(
	struct ecryptfs_ctx *ctx, struct param_node *node,
	struct val_node **mnt_params, void **foo)
{
	struct ecryptfs_subgraph_ctx *subgraph_ctx;	
	int rc = DEFAULT_TOK;

	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_ctx->openssl_data.path, "%s",
			   node->val)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = DEFAULT_TOK;
out:
	return rc;
}

static int tf_ecryptfs_openssl_gen_key_param_node_passphrase(
	struct ecryptfs_ctx *ctx, struct param_node *node,
	struct val_node **mnt_params, void **foo)
{
	struct ecryptfs_subgraph_ctx *subgraph_ctx;	
	int rc = DEFAULT_TOK;

	subgraph_ctx = (struct ecryptfs_subgraph_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_ctx->openssl_data.passphrase, "%s",
			   node->val)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = ecryptfs_openssl_generate_key(&subgraph_ctx->openssl_data))) {
		syslog(LOG_ERR, "%s: Error generating key to file [%s]; "
		       "rc = [%d]\n", __FUNCTION__,
		       subgraph_ctx->openssl_data.path, rc);
		rc = MOUNT_ERROR;
		goto out;
	}
out:
	return rc;
}

#define ECRYPTFS_OPENSSL_GEN_KEY_PARAM_NODE_KEYFILE 0
#define ECRYPTFS_OPENSSL_GEN_KEY_PARAM_NODE_PASSPHRASE 1
static struct param_node ecryptfs_openssl_gen_key_param_nodes[] = {
	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"keyfile"},
	 .prompt = "SSL key file path",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .suggested_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = "",
		 .next_token = &ecryptfs_openssl_gen_key_param_nodes[
			 ECRYPTFS_OPENSSL_GEN_KEY_PARAM_NODE_PASSPHRASE],
		 .trans_func = &tf_ecryptfs_openssl_gen_key_param_node_keyfile}}},
	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"passphrase"},
	 .prompt = "Passphrase",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .suggested_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_MASK_OUTPUT | VERIFY_VALUE,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func =
		         &tf_ecryptfs_openssl_gen_key_param_node_passphrase}}}
};

#define SSL_KEY_SOURCE_TOK 0
#define SSL_KEY_FILE_TOK 1
#define SSL_PASSPHRASE_METHOD_TOK 2
#define SSL_USER_PROVIDED_PASSWD_TOK 3
#define SSL_FILE_PASSWD_TOK 4
#define SSL_FD_PASSWD_TOK 5
static struct param_node ssl_param_nodes[] = {
	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"openssl_keysource", "keysource"},
	 .prompt = "Key source",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "keyfile",
	 .flags = ECRYPTFS_PARAM_FLAG_NO_VALUE,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = "OpenSSL Key File",
		 .next_token = &ssl_param_nodes[SSL_KEY_FILE_TOK],
		 .trans_func = NULL}}}, /* Add more options here later */

	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"openssl_keyfile", "keyfile"},
	 .prompt = "PEM key file",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "default", /* The decision graph code will
				    * just follow a "default"
				    * transition node */
		 .pretty_val = "Passphrase Method",
		 .next_token = &ssl_param_nodes[SSL_PASSPHRASE_METHOD_TOK],
		 .trans_func = tf_ssl_keyfile}}},

	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"openssl_passwd_specification_method",
			   "passwd_specification_method"},
	 .prompt = "Method of providing the passphrase",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .suggested_val = "openssl_passwd",
	 /* An implicit transition takes place if one of the key
	  * module parameters that are the target of one of the
	  * transition nodes already exists in the provided parameter
	  * list. */
	 .flags = (DISPLAY_TRANSITION_NODE_VALS | ECRYPTFS_DISPLAY_PRETTY_VALS
		   | ECRYPTFS_PARAM_FLAG_ECHO_INPUT
		   | ECRYPTFS_ALLOW_IMPLICIT_TRANSITION),
	 .num_transitions = 3,
	 .tl = {{.val = "openssl_passwd",
		 .pretty_val = "openssl_passwd: Enter on Console",
		 .next_token = &ssl_param_nodes[SSL_USER_PROVIDED_PASSWD_TOK],
		 .trans_func = NULL},
		{.val = "openssl_passwd_file",
		 .pretty_val = "openssl_passwd_file: File Containing Passphrase",
		 .next_token = &ssl_param_nodes[SSL_FILE_PASSWD_TOK],
		 .trans_func = NULL},
		{.val = "openssl_passwd_fd",
		 .pretty_val = ("openssl_passwd_fd: File Descriptor for File "
				"Containing Passphrase"),
		 .next_token = &ssl_param_nodes[SSL_FD_PASSWD_TOK],
		 .trans_func = NULL}}},

	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"openssl_passwd", "passwd"},
	 .prompt = "Passphrase",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = STDIN_REQUIRED | ECRYPTFS_PARAM_FLAG_MASK_OUTPUT,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_ssl_passwd}}},

	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"openssl_passwd_file", "passwd_file"},
	 .prompt = "Passphrase File",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = STDIN_REQUIRED | ECRYPTFS_PARAM_FLAG_ECHO_INPUT
		  | ECRYPTFS_NONEMPTY_VALUE_REQUIRED,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_ssl_passwd_file}}},

	{.num_mnt_opt_names = 2,
	 .mnt_opt_names = {"openssl_passwd_fd", "passwd_fd"},
	 .prompt = "Passphrase File Descriptor",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = STDIN_REQUIRED | ECRYPTFS_PARAM_FLAG_ECHO_INPUT
		  | ECRYPTFS_NONEMPTY_VALUE_REQUIRED,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_ssl_passwd_fd}}}

};

/**
 * tf_openssl_enter
 * @ctx: The current applicable libecryptfs context struct
 * @node: The param_node from which we are transitioning
 * @head: The head of the name/value pair list that is being
 *        constructed as the decision graph is being traversed
 * @foo: Arbitrary state information for the current subgraph
 *
 * Each transition from one node in the decision graph to another node
 * can have a function executed on the transition event. A transition
 * into any given subgraph may require certain housekeeping and
 * initialization functions to occur.
 *
 * The decision graph engine forwards along an arbitrary data
 * structure among the nodes of any subgraph. The logic in the
 * subgraph can use that data structure to access and maintain
 * arbitrary status information that is unique to the function of that
 * subgraph.
 */
static int tf_openssl_enter(struct ecryptfs_ctx *ctx,
			    struct param_node *param_node,
			    struct val_node **mnt_params, void **foo)
{
	struct ecryptfs_subgraph_ctx *subgraph_ctx;
	int rc;

	if ((subgraph_ctx = malloc(sizeof(struct ecryptfs_subgraph_ctx)))
	    == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(subgraph_ctx, 0, sizeof(struct ecryptfs_subgraph_ctx));
	if ((rc = ecryptfs_find_key_mod(&subgraph_ctx->key_mod, ctx,
					param_node->val))) {
		syslog(LOG_ERR, "%s: Cannot find key_mod for param_node with "
		       "val = [%s]\n", __FUNCTION__, param_node->val);
		goto out;
	}
	(*foo) = (void *)subgraph_ctx;
out:
	return rc;
}

struct transition_node openssl_transition = {
	.val = "openssl",
	.pretty_val = "OpenSSL module",
	.next_token = &(ssl_param_nodes[SSL_KEY_SOURCE_TOK]),
	.trans_func = tf_openssl_enter
};

static int ecryptfs_openssl_get_param_subgraph_trans_node(
	struct transition_node **trans, uint32_t version)
{
	if ((version & ECRYPTFS_VERSIONING_PUBKEY) == 0)
		return -1;
	(*trans) = &openssl_transition;
	return 0;
}

struct transition_node openssl_gen_key_transition = {
	.val = "openssl",
	.pretty_val = "OpenSSL module",
	.next_token = &(ecryptfs_openssl_gen_key_param_nodes[
				ECRYPTFS_OPENSSL_GEN_KEY_PARAM_NODE_KEYFILE]),
	.trans_func = tf_openssl_enter
};

static int ecryptfs_openssl_get_gen_key_param_subgraph_trans_node(
	struct transition_node **trans, uint32_t version)
{
	if ((version & ECRYPTFS_VERSIONING_PUBKEY) == 0)
		return -1;
	(*trans) = &openssl_gen_key_transition;
	return 0;
}

int ecryptfs_openssl_finalize(void)
{
	return 0;
}

static int ecryptfs_openssl_init(char **alias)
{
	uid_t id;
	struct passwd *pw;
	struct param_node *gen_key_keyfile_param_node =
		&ecryptfs_openssl_gen_key_param_nodes[
			ECRYPTFS_OPENSSL_GEN_KEY_PARAM_NODE_KEYFILE];
	int rc = 0;

	if (asprintf(alias, "openssl") == -1) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Out of memory\n");
		goto out;
	}
	id = getuid();
	pw = getpwuid(id);
	if (!pw) {
		rc = -EIO;
		goto out;
	}
	if ((rc = asprintf(&ssl_param_nodes[SSL_KEY_FILE_TOK].suggested_val,
			   "%s/.ecryptfs/pki/openssl/key.pem",
			   pw->pw_dir)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = asprintf(&gen_key_keyfile_param_node->suggested_val,
			   "%s/.ecryptfs/pki/openssl/key.pem",
			   pw->pw_dir)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
out:
	return rc;
}

static struct ecryptfs_key_mod_ops ecryptfs_openssl_ops = {
	&ecryptfs_openssl_init,
	NULL,
	&ecryptfs_openssl_get_gen_key_param_subgraph_trans_node,
	NULL,
	&ecryptfs_openssl_get_param_subgraph_trans_node,
	&ecryptfs_openssl_get_blob,
	NULL,
	&ecryptfs_openssl_get_key_sig,
	NULL,
	&ecryptfs_openssl_encrypt,
	&ecryptfs_openssl_decrypt,
	NULL,
	&ecryptfs_openssl_finalize
};

struct ecryptfs_key_mod_ops *get_key_mod_ops(void)
{
	return &ecryptfs_openssl_ops;
}
