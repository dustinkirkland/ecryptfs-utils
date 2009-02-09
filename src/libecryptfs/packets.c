/**
 * Userspace side of communications with eCryptfs kernel module.
 *
 * Copyright (C) 2004-2006 International Business Machines Corp.
 *   Author(s): Trevor S. Highland <trevor.highland@gmail.com>
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

#include <errno.h>
#ifndef S_SPLINT_S
#include <syslog.h>
#include <stdio.h>
#endif
#include <string.h>
#include <unistd.h>
#include <keyutils.h>
#include <stdlib.h>
#include "config.h"
#include "../include/ecryptfs.h"

#define ECRYPTFS_PACKET_STATUS_GOOD 0
#define ECRYPTFS_PACKET_STATUS_BAD -1

/**
 * key_mod_encrypt
 * @encrypted_key: This function will allocate this memory and encrypt
 *                 the key into it
 * @encrypted_key_size: The size of the encrypted key; note that the
 *                      actual amount of memory allocated by this
 *                      function may be more than this
 * @ctx:
 * @auth_tok: The authentication token structure in the user session
 *            keyring; this contains the key module state blob
 * @decrypted_key:
 * @decrypted_key_size:
 *
 *
 *
 * Called from parse_packet()
 */
static int
key_mod_encrypt(char **encrypted_key, size_t *encrypted_key_size,
		struct ecryptfs_ctx *ctx, struct ecryptfs_auth_tok *auth_tok,
		char *decrypted_key, size_t decrypted_key_size)
{
	struct ecryptfs_key_mod *key_mod;
	int rc;

	if (ecryptfs_find_key_mod(&key_mod, ctx,
				  auth_tok->token.private_key.key_mod_alias)) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Failed to locate desired key module\n");
		goto out;
	}
	/* TODO: Include support for a hint rather than just a blob */
	if ((rc = key_mod->ops->encrypt(NULL, encrypted_key_size, decrypted_key,
					decrypted_key_size,
					auth_tok->token.private_key.data,
					ECRYPTFS_BLOB_TYPE_BLOB))) {
		syslog(LOG_ERR, "Error attempting to get encrypted key size "
		       "from key module; rc = [%d]\n", rc);
		goto out;
	}
	if ((*encrypted_key_size) == 0) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Encrypted key size reported by key module "
		       "encrypt function is 0\n");
		goto out;
	}
	/* The first call just told us how much memory to
	 * allocate. The actual key size may be less, so we don't
	 * worry about ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES until the
	 * second call. */
	if (((*encrypted_key) = malloc(*encrypted_key_size)) == NULL) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to allocate memory: [%m]\n");
		goto out;
	}
	if ((rc = key_mod->ops->encrypt((*encrypted_key), encrypted_key_size,
					decrypted_key, decrypted_key_size,
					auth_tok->token.private_key.data,
					ECRYPTFS_BLOB_TYPE_BLOB))) {
		syslog(LOG_ERR, "Failed to encrypt key; rc = [%d]\n", rc);
		goto out;
	}
	if ((*encrypted_key_size) > ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Encrypted key size reported by key module "
		       "encrypt function is [%zu]; max is [%d]\n",
		       (*encrypted_key_size), ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES);
		free(*encrypted_key);
		(*encrypted_key_size) = 0;
		goto out;
	}
out:
	return rc;
}

static int
key_mod_decrypt(char **decrypted_key, size_t *decrypted_key_size,
		struct ecryptfs_ctx *ctx, struct ecryptfs_auth_tok *auth_tok,
		char *encrypted_key, size_t encrypted_key_size)
{
	struct ecryptfs_key_mod *key_mod;
	int rc;

	if (ecryptfs_find_key_mod(&key_mod, ctx,
				  auth_tok->token.private_key.key_mod_alias)) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Failed to locate desired key module\n");
		goto out;
	}
	if ((rc = key_mod->ops->decrypt(NULL, decrypted_key_size,
					encrypted_key, encrypted_key_size,
					auth_tok->token.private_key.data,
					ECRYPTFS_BLOB_TYPE_BLOB))) {
		syslog(LOG_ERR, "Failed to get size for decrypted key\n");
		goto out;
	}
	if ((*decrypted_key_size) == 0) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Decrypted key size reported by key module "
		       "decrypt function is 0\n");
		goto out;
	}
	/* The first call just told us how much memory to
	 * allocate. The actual key size may be less, so we don't
	 * worry about ECRYPTFS_MAX_KEY_BYTES until the second
	 * call. */
	if (((*decrypted_key) = malloc(*decrypted_key_size)) == NULL) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Failed to allocate memory\n");
		goto out;
	}
	if ((rc = key_mod->ops->decrypt(*decrypted_key, decrypted_key_size,
					encrypted_key, encrypted_key_size,
					auth_tok->token.private_key.data,
					ECRYPTFS_BLOB_TYPE_BLOB))) {
		syslog(LOG_ERR, "Failed to decrypt key\n");
		goto out;
	}
	if ((*decrypted_key_size) > ECRYPTFS_MAX_KEY_BYTES) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Decrypted key size reported by key module "
		       "decrypt function is [%zu]; max is [%d]\n",
		       (*decrypted_key_size), ECRYPTFS_MAX_KEY_BYTES);
		free(*decrypted_key);
		(*decrypted_key_size) = 0;
		goto out;
	}
out:
	return rc;
}

static int write_failure_packet(size_t tag,
				struct ecryptfs_message **reply)
{
	unsigned char *data;
	size_t i = 0;
	int rc = 0;

	*reply = malloc(sizeof(struct ecryptfs_message) + 2);
	if (!*reply) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to allocate memory: %m\n");
		goto out;
	}
	data = (*reply)->data;
	data[i++] = tag;
	data[i++] = ECRYPTFS_PACKET_STATUS_BAD;
	(*reply)->data_len = i;
out:
	return rc;
}

static int write_tag_65_packet(unsigned char *key, size_t key_size,
			       struct ecryptfs_message **reply)
{
	unsigned char *data;
	size_t data_len;
	size_t length_size;
	size_t i = 0;
	int rc = 0;

	data_len = key_size + 4;
	*reply = malloc(sizeof(struct ecryptfs_message) + data_len);
	if (!*reply) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to allocate memory: %m\n");
		goto out;
	}
	data = (*reply)->data;
	data[i++] = ECRYPTFS_TAG_65_PACKET;
	data[i++] = ECRYPTFS_PACKET_STATUS_GOOD;
	rc = ecryptfs_write_packet_length((char*)&data[i], key_size, &length_size);
	if (rc) {
		syslog(LOG_ERR, "Invalid packet format\n");
		goto out;
	}
	i += length_size;
	memcpy(&data[i], key, key_size);
	i += key_size;
	(*reply)->data_len = i;
out:
	return rc;
}

static int
write_tag_67_packet(char *key, size_t key_size,
		    struct ecryptfs_message **reply)
{
	unsigned char *data;
	size_t data_len;
	size_t length_size;
	size_t i = 0;
	int rc = 0;

	data_len = key_size + 4;
	*reply = malloc(sizeof(struct ecryptfs_message) + data_len);
	if (!*reply) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to allocate memory: %m\n");
		goto out;
	}
	data = (*reply)->data;
	data[i++] = ECRYPTFS_TAG_67_PACKET;
	data[i++] = ECRYPTFS_PACKET_STATUS_GOOD;
	rc = ecryptfs_write_packet_length((char *)&data[i], key_size, &length_size);
	if (rc) {
		syslog(LOG_ERR, "Invalid packet format\n");
		goto out;
	}
	i += length_size;
	memcpy(&data[i], key, key_size);
	i += key_size;
	(*reply)->data_len = data_len;
out:
	return rc;
}

int parse_packet(struct ecryptfs_ctx *ctx,
		 struct ecryptfs_message *emsg,
		 struct ecryptfs_message **reply)
{
	struct ecryptfs_auth_tok *auth_tok = NULL;
	size_t i = 0;
	size_t data_size;
	size_t key_size;
	size_t length_size;
	size_t key_out_size;
	unsigned char *signature = NULL;
	unsigned char packet_type;
	char *key = NULL;
	char *key_out = NULL;
	key_serial_t key_sub;
	int rc;

	packet_type = emsg->data[i++];
	if ((rc = ecryptfs_parse_packet_length(&emsg->data[i], &data_size,
					       &length_size))) {
		syslog(LOG_ERR, "Invalid packet format\n");
		goto write_failure;
	}
	i += length_size;
	signature = malloc(data_size + 1);
	if (!signature) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to allocate memory: %m\n");
		goto write_failure;
	}
	memcpy(signature, &emsg->data[i], data_size);
	signature[data_size] = '\0';
	i += data_size;
	rc = ecryptfs_parse_packet_length(&emsg->data[i], &key_size,
					  &length_size);
	if (rc) {
		syslog(LOG_ERR, "Invalid packet format\n");
		goto write_failure;
	}
	i += length_size;
	if ((key = malloc(key_size)) == NULL) {
		rc = -ENOMEM;
		syslog(LOG_ERR, "Failed to allocate memory\n");
		goto write_failure;
	}
	memcpy(key, &emsg->data[i], key_size);
	i += key_size;
	key_sub = request_key("user", (char *)signature, NULL,
			      KEY_SPEC_USER_KEYRING);
	if (key_sub < 0) {
		syslog(LOG_ERR, "Could not find key with signature: "
		       "[%s]\n", signature);
		rc = -EINVAL;
		goto write_failure;
	}
	rc = keyctl_read_alloc(key_sub, (void **)(&auth_tok));
	switch (packet_type) {
	case ECRYPTFS_TAG_64_PACKET:
		if ((rc = key_mod_decrypt(&key_out, &key_out_size, ctx,
					  auth_tok, key, key_size))) {
			syslog(LOG_ERR, "Failed to decrypt key; rc = [%d]\n",
			       rc);
			rc = write_failure_packet(ECRYPTFS_TAG_65_PACKET,
						  reply);
			goto write_failure;
		}
		if ((rc = write_tag_65_packet((unsigned char *)key_out,
					      key_out_size, reply))) {
			syslog(LOG_ERR, "Failed to write decrypted "
			       "key via tag 65 packet\n");
			goto write_failure;
		}
		break;
	case ECRYPTFS_TAG_66_PACKET:
		rc = key_mod_encrypt(&key_out, &key_out_size, ctx, auth_tok,
				     key, key_size);
		if (rc) {
			syslog(LOG_ERR, "Failed to encrypt public "
			       "key\n");
			goto write_failure;
		}
		rc = write_tag_67_packet(key_out, key_out_size, reply);
		if (rc) {
			syslog(LOG_ERR, "Failed to write encrypted "
			       "key to tag 67 packet\n");
			goto write_failure;
		}
		break;
	default:
		syslog(LOG_ERR, "Unrecognized packet type: [%d]\n",
		       packet_type);
		rc = -EINVAL;
		break;
	}
	free(key);
	free(signature);
	free(key_out);
	memset(auth_tok, 0, (sizeof(struct ecryptfs_auth_tok)
			     + auth_tok->token.private_key.data_len));
	free(auth_tok);
	return rc;
write_failure:
	if(packet_type == ECRYPTFS_TAG_66_PACKET)
		rc = write_failure_packet(ECRYPTFS_TAG_67_PACKET, reply);
	else
		rc = write_failure_packet(ECRYPTFS_TAG_65_PACKET, reply);
	free(key);
	free(signature);
	free(key_out);
	if (auth_tok) {
		memset(auth_tok, 0, (sizeof(struct ecryptfs_auth_tok)
				     + auth_tok->token.private_key.data_len));
		free(auth_tok);
	}
	return rc;
}
