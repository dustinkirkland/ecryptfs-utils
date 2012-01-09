/**
 * Copyright (C) 2006-2007 International Business Machines Corp.
 * Author(s): Mike Halcrow <mhalcrow@us.ibm.com>
 *            Kent Yoder <kyoder@users.sf.net>
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
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <time.h>
#include <unistd.h>
#include <errno.h>
#include <trousers/tss.h>
#include <trousers/trousers.h>
#include <openssl/sha.h>
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"

#define ECRYPTFS_TSPI_DEFAULT_MAX_NUM_CONNECTIONS 10

#undef DEBUG

#ifdef DEBUG
#define DBGSYSLOG(x, ...)	syslog(LOG_DEBUG, x, ##__VA_ARGS__)
#define DBG_print_hex(a,b)	print_hex(a,b)

static void
print_hex(BYTE *buf, uint32_t len)
{
	uint32_t i = 0, j;

	while (i < len) {
		for (j=0; (j < 15) && (i < len); j++, i++)
			syslog(LOG_INFO, "%02x\n", buf[i] & 0xff);
	}
}

#else
#define LOG()
#define DBGSYSLOG(x, ...)
#define DBG_print_hex(a,b)
#endif

static TSS_UUID ecryptfs_tspi_srk_uuid = TSS_UUID_SRK;

static struct key_mapper {
	TSS_UUID uuid;
	TSS_HKEY hKey;
	struct key_mapper *next;
} *mapper = NULL;

struct tspi_data {
	TSS_UUID uuid;
};

static void ecryptfs_tspi_to_hex(char *dst, char *src, int src_size)
{
	int x;

	for (x = 0; x < src_size; x++)
		sprintf(&dst[x * 2], "%.2x", (unsigned char)src[x]);
}

static int ecryptfs_tspi_generate_signature(char *sig, BYTE *n, uint32_t nbytes)
{
	int len, i;
	unsigned char hash[SHA1_DIGEST_LENGTH];
	unsigned char *data = NULL;
	BYTE e[] = { 1, 0, 1 }; /* The e for all TPM RSA keys */
	int rc = 0;

	len = 10 + nbytes + sizeof(e);
	if ((data = malloc(3 + len)) == NULL) {
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
	data[i++] = ((nbytes * 8) >> 8);
	data[i++] = (nbytes * 8);
	memcpy(&data[i], n, nbytes);
	i += nbytes;
	data[i++] = ((sizeof(e) * 8) >> 8);
	data[i++] = (sizeof(e) * 8);
	memcpy(&data[i], e, sizeof(e));
	i += sizeof(e);
	SHA1(data, len + 3, hash);
	ecryptfs_tspi_to_hex(sig, (char *)hash, ECRYPTFS_SIG_SIZE);
	sig[ECRYPTFS_SIG_SIZE_HEX] = '\0';
out:
	free(data);
	return rc;
}

static int
ecryptfs_tspi_deserialize(struct tspi_data *tspi_data, unsigned char *blob)
{
	int rc = 0;

	memcpy(&tspi_data->uuid, blob, sizeof(TSS_UUID));

	return rc;
}

static int ecryptfs_tspi_get_key_sig(unsigned char *sig, unsigned char *blob)
{
	struct tspi_data tspi_data;
	BYTE *n;
	uint32_t size_n;
	TSS_RESULT result;
	TSS_HCONTEXT h_ctx;
	TSS_HKEY hKey;
	int rc = 0;

	ecryptfs_tspi_deserialize(&tspi_data, blob);
	if ((result = Tspi_Context_Create(&h_ctx)) != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_Create failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	DBG_print_hex((BYTE *)&tspi_data.uuid, sizeof(TSS_UUID));
	if ((result = Tspi_Context_GetKeyByUUID(h_ctx, TSS_PS_TYPE_USER,
						tspi_data.uuid, &hKey))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_GetKeyByUUID failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_GetAttribData(hKey, TSS_TSPATTRIB_RSAKEY_INFO,
					 TSS_TSPATTRIB_KEYINFO_RSA_MODULUS,
					 &size_n, &n))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_GetAttribUint32 failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	rc = ecryptfs_tspi_generate_signature((char *)sig, n, size_n);
out:
	return rc;
}

static pthread_mutex_t encrypt_lock = PTHREAD_MUTEX_INITIALIZER;

struct ecryptfs_tspi_connect_ticket;

struct ecryptfs_tspi_connect_ticket {
	struct ecryptfs_tspi_connect_ticket *next;
#define ECRYPTFS_TSPI_TICKET_CTX_INITIALIZED 0x00000001
	uint32_t flags;
	pthread_mutex_t lock;
	pthread_mutex_t wait;
	TSS_HCONTEXT tspi_ctx;
	uint32_t num_pending;
};

static pthread_mutex_t ecryptfs_ticket_list_lock = PTHREAD_MUTEX_INITIALIZER;

static uint32_t ecryptfs_tspi_num_tickets_free;
static uint32_t ecryptfs_tspi_num_tickets_used;
static uint32_t ecryptfs_tspi_num_tickets_connected;

static struct ecryptfs_tspi_connect_ticket *ptr_to_free_ticket_list_head = NULL;
static struct ecryptfs_tspi_connect_ticket *ptr_to_used_ticket_list_head = NULL;

static int
ecryptfs_tspi_grab_ticket(struct ecryptfs_tspi_connect_ticket **ret_ticket)
{
	struct ecryptfs_tspi_connect_ticket *ticket;
	int rc = 0;

	(*ret_ticket) = NULL;
	pthread_mutex_lock(&ecryptfs_ticket_list_lock);
	ticket = ptr_to_free_ticket_list_head;
	if (!ticket) {
		struct ecryptfs_tspi_connect_ticket *tmp;

		ticket = ptr_to_used_ticket_list_head;
		pthread_mutex_lock(&ticket->lock);
		tmp = ticket->next;
		while (tmp) {
			struct ecryptfs_tspi_connect_ticket *next;

			pthread_mutex_lock(&tmp->lock);
			next = tmp->next;
			if (tmp->num_pending < ticket->num_pending) {
				pthread_mutex_unlock(&ticket->lock);
				ticket = tmp;
			} else
				pthread_mutex_unlock(&tmp->lock);
			tmp = next;
		}
		ticket->num_pending++;
		pthread_mutex_unlock(&ticket->lock);
	} else {
		while (ticket) {
			struct ecryptfs_tspi_connect_ticket *next;

			pthread_mutex_lock(&ticket->lock);
			next = ticket->next;
			if (ticket->flags
			    & ECRYPTFS_TSPI_TICKET_CTX_INITIALIZED) {
				pthread_mutex_unlock(&ticket->lock);
				break;
			}
			pthread_mutex_unlock(&ticket->lock);
			ticket = next;
		}
		if (!ticket) {
			TSS_RESULT result;

			ticket = ptr_to_free_ticket_list_head;
			pthread_mutex_lock(&ticket->lock);
			if ((result = Tspi_Context_Create(&ticket->tspi_ctx))
			    != TSS_SUCCESS) {
				syslog(LOG_ERR, "Tspi_Context_Create failed: "
				       "[%s]\n", Trspi_Error_String(result));
				rc = -EIO;
				pthread_mutex_unlock(&ticket->lock);
				pthread_mutex_unlock(
					&ecryptfs_ticket_list_lock);
				goto out;
			}
			if ((result = Tspi_Context_Connect(ticket->tspi_ctx,
							   NULL))
			    != TSS_SUCCESS) {
				syslog(LOG_ERR, "Tspi_Context_Connect "
				       "failed: [%s]\n",
				       Trspi_Error_String(result));
				rc = -EIO;
				pthread_mutex_unlock(&ticket->lock);
				pthread_mutex_unlock(
					&ecryptfs_ticket_list_lock);
				goto out;
			}
			ticket->flags |= ECRYPTFS_TSPI_TICKET_CTX_INITIALIZED;
			ecryptfs_tspi_num_tickets_connected++;
			pthread_mutex_unlock(&ticket->lock);
		}
		pthread_mutex_lock(&ticket->lock);
		ptr_to_free_ticket_list_head = ticket->next;
		ticket->next = ptr_to_used_ticket_list_head;
		ptr_to_used_ticket_list_head = ticket;
		ecryptfs_tspi_num_tickets_free--;
		ecryptfs_tspi_num_tickets_used++;
		ticket->num_pending++;
		pthread_mutex_unlock(&ticket->lock);
	}
	pthread_mutex_unlock(&ecryptfs_ticket_list_lock);
	pthread_mutex_lock(&ticket->wait);
	pthread_mutex_lock(&ticket->lock);
	ticket->num_pending--;
	pthread_mutex_unlock(&ticket->lock);
	(*ret_ticket) = ticket;
out:
	return rc;
}

static int
ecryptfs_tspi_release_ticket(struct ecryptfs_tspi_connect_ticket *ticket)
{
	int rc = 0;

	pthread_mutex_lock(&ecryptfs_ticket_list_lock);
	pthread_mutex_unlock(&ticket->wait);
	ptr_to_used_ticket_list_head = ticket->next;
	ticket->next = ptr_to_free_ticket_list_head;
	ptr_to_free_ticket_list_head = ticket;
	ecryptfs_tspi_num_tickets_free++;
	ecryptfs_tspi_num_tickets_used--;
	pthread_mutex_unlock(&ecryptfs_ticket_list_lock);
	return rc;
}

static int
ecryptfs_tspi_encrypt(char *to, size_t *to_size, char *from, size_t from_size,
		      unsigned char *blob, int blob_type)
{
	static TSS_HPOLICY h_srk_policy = 0;
	static TSS_HKEY h_srk = 0;
	TSS_RESULT result;
	TSS_HKEY hKey;
	TSS_HENCDATA h_encdata;
	uint32_t encdata_size;
	BYTE *encdata;
	struct tspi_data tspi_data;
	struct ecryptfs_tspi_connect_ticket *ticket;
	int rc = 0;
	BYTE wellknown[] = TSS_WELL_KNOWN_SECRET;

	pthread_mutex_lock(&encrypt_lock);
	(*to_size) = 0;
	ecryptfs_tspi_deserialize(&tspi_data, blob);
	DBG_print_hex((BYTE *)&tspi_data.uuid, sizeof(TSS_UUID));
	rc = ecryptfs_tspi_grab_ticket(&ticket);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to get TSPI connection "
		       "ticket; rc = [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	if ((result = Tspi_Context_LoadKeyByUUID(ticket->tspi_ctx,
						 TSS_PS_TYPE_SYSTEM,
						 ecryptfs_tspi_srk_uuid,
						 &h_srk)) != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_GetPolicyObject(h_srk, TSS_POLICY_USAGE,
					   &h_srk_policy))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_GetPolicyObject failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Policy_SetSecret(h_srk_policy,
					    TSS_SECRET_MODE_SHA1,
					    sizeof(wellknown), wellknown))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Policy_SetSecret failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Context_CreateObject(ticket->tspi_ctx,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_SEAL, &h_encdata))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_CreateObject failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Context_LoadKeyByUUID(ticket->tspi_ctx,
						 TSS_PS_TYPE_USER,
						 tspi_data.uuid, &hKey))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Data_Seal(h_encdata, hKey, from_size, 
				     (unsigned char *)from, 0))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Data_Seal failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_GetAttribData(h_encdata, TSS_TSPATTRIB_ENCDATA_BLOB,
					 TSS_TSPATTRIB_ENCDATABLOB_BLOB,
					 &encdata_size, &encdata))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_GetAttribData failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	(*to_size) = encdata_size;
	if (to)
		memcpy(to, encdata, (*to_size));
	Tspi_Context_FreeMemory(ticket->tspi_ctx, encdata);
out:
	pthread_mutex_unlock(&encrypt_lock);
	if (ticket)
		ecryptfs_tspi_release_ticket(ticket);
	return rc;
}

static pthread_mutex_t decrypt_lock = PTHREAD_MUTEX_INITIALIZER;

static int
ecryptfs_tspi_decrypt(char *to, size_t *to_size, char *from, size_t from_size,
		      unsigned char *blob, int blob_type)
{
	static TSS_HPOLICY h_srk_policy = 0;
	static TSS_HKEY h_srk = 0;
	static TSS_HENCDATA h_encdata;
	uint32_t encdata_bytes;
	BYTE *encdata;
	struct tspi_data tspi_data;
	struct key_mapper *walker, *new_mapper;
	struct ecryptfs_tspi_connect_ticket *ticket;
	TSS_RESULT result;
	int rc = 0;
	BYTE wellknown[] = TSS_WELL_KNOWN_SECRET;

	pthread_mutex_lock(&decrypt_lock);
	ecryptfs_tspi_deserialize(&tspi_data, blob);
	rc = ecryptfs_tspi_grab_ticket(&ticket);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to get TSPI connection "
		       "ticket; rc = [%d]\n", __FUNCTION__, rc);
		goto out;
	}
	if ((result = Tspi_Context_LoadKeyByUUID(ticket->tspi_ctx,
						TSS_PS_TYPE_SYSTEM,
						ecryptfs_tspi_srk_uuid,
						&h_srk)) != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_LoadKeyByUUID failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_GetPolicyObject(h_srk, TSS_POLICY_USAGE,
					   &h_srk_policy))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_GetPolicyObject failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Policy_SetSecret(h_srk_policy,
					    TSS_SECRET_MODE_SHA1,
					    sizeof(wellknown), wellknown))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Policy_SetSecret failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Context_CreateObject(ticket->tspi_ctx,
						TSS_OBJECT_TYPE_ENCDATA,
						TSS_ENCDATA_SEAL, &h_encdata))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Context_CreateObject failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	for (walker = mapper; walker; walker = walker->next)
		if (!memcmp(&walker->uuid, &tspi_data.uuid, sizeof(TSS_UUID)))
			break;
	if (!walker) {
		if ((new_mapper = calloc(1, sizeof(struct key_mapper)))
		    == NULL) {
			syslog(LOG_ERR, "calloc failed: [%m]\n");
			rc = -EIO;
			goto out;
		}
		if ((result = Tspi_Context_LoadKeyByUUID(ticket->tspi_ctx,
							 TSS_PS_TYPE_USER,
							 tspi_data.uuid,
							 &new_mapper->hKey))
		    != TSS_SUCCESS) {
			syslog(LOG_ERR,
			       "Tspi_Context_LoadKeyByUUID failed: [%s]\n",
			       Trspi_Error_String(result));
			rc = -EIO;
			goto out;
		}
		DBGSYSLOG("New key object: [0x%x]\n", new_mapper->hKey);
		memcpy(&new_mapper->uuid, &tspi_data.uuid, sizeof(TSS_UUID));
		new_mapper->next = mapper;
		walker = mapper = new_mapper;
	}
	if ((result = Tspi_SetAttribData(h_encdata, TSS_TSPATTRIB_ENCDATA_BLOB,
					 TSS_TSPATTRIB_ENCDATABLOB_BLOB,
					 from_size, (BYTE *)from))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_SetAttribData failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	if ((result = Tspi_Data_Unseal(h_encdata, walker->hKey,
				       &encdata_bytes, &encdata))
	    != TSS_SUCCESS) {
		syslog(LOG_ERR, "Tspi_Data_Unseal failed: [%s]\n",
		       Trspi_Error_String(result));
		rc = -EIO;
		goto out;
	}
	(*to_size) = encdata_bytes;
	if (to)
		memcpy(to, encdata, encdata_bytes);
	Tspi_Context_FreeMemory(ticket->tspi_ctx, encdata);
	rc = 0;
out:
	pthread_mutex_unlock(&decrypt_lock);
	if (ticket)
		ecryptfs_tspi_release_ticket(ticket);
	return rc;
}

#define ECRYPTFS_KEY_MOD_PARAM_TSPI_UUID 1
static struct key_mod_param tspi_params[] = {
	{.id = ECRYPTFS_KEY_MOD_PARAM_TSPI_UUID,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .option = "tspi_uuid",
	 .description = "tspi_uuid",
	 .suggested_val = NULL,
	 .default_val = NULL,
	 .val = NULL},
	{.id = 0,
	 .flags = 0,
	 .option = NULL,
	 .description = NULL,
	 .suggested_val = NULL,
	 .default_val = NULL,
	 .val = NULL}
};

static uint32_t tspi_num_params = 1;

/**
 * Convert user input string into TSS_UUID data type
 */
static void string_to_uuid(TSS_UUID *uuid, char *str)
{
	BYTE tmp[(sizeof(uint32_t) * 2 + 1)];
	uint32_t i, l;

	tmp[sizeof(uint32_t) * 2] = '\0';
	for (i = 0; i < (sizeof(TSS_UUID) * 2);
	     i += (sizeof(uint32_t) * 2)) {
		memcpy(tmp, &str[i], sizeof(uint32_t) * 2);
		l = strtoul((char *)tmp, NULL, 16);
		l = htonl(l);
		memcpy(&((BYTE *)uuid)[i/2], &l, sizeof(uint32_t));
	}
}

static int ecryptfs_tspi_init(char **alias)
{
	int i;

	int rc = 0;

	if (asprintf(alias, "tspi") == -1) {
		syslog(LOG_ERR, "Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	ecryptfs_tspi_num_tickets_free = 0;
	ecryptfs_tspi_num_tickets_used = 0;
	ecryptfs_tspi_num_tickets_connected = 0;
	for (i = 0; i < ECRYPTFS_TSPI_DEFAULT_MAX_NUM_CONNECTIONS; i++) {
		struct ecryptfs_tspi_connect_ticket *ticket;

		ticket = malloc(sizeof(struct ecryptfs_tspi_connect_ticket));
		if (!ticket) {
			rc = -ENOMEM;
			goto out;
		}
		pthread_mutex_init(&ticket->lock, NULL);
		ticket->flags = 0;
		ticket->tspi_ctx = 0;
		ticket->num_pending = 0;
		pthread_mutex_lock(&ecryptfs_ticket_list_lock);		
		ticket->next = ptr_to_free_ticket_list_head;
		ptr_to_free_ticket_list_head = ticket;
		ecryptfs_tspi_num_tickets_free++;
		pthread_mutex_unlock(&ecryptfs_ticket_list_lock);
	}
out:
	return rc;
}

static int
ecryptfs_tspi_get_params(struct key_mod_param **params, uint32_t *num_params)
{
	(*params) = tspi_params;
	(*num_params) = tspi_num_params;
	return 0;
}

static int ecryptfs_tspi_serialize(unsigned char *blob, size_t *blob_size,
				   struct tspi_data *tspi_data)
{
	int rc = 0;

	(*blob_size) = sizeof(TSS_UUID);
	if (blob == NULL)
		goto out;
	memcpy(blob, &tspi_data->uuid, sizeof(TSS_UUID));
out:
	return rc;
}

static int
ecryptfs_tspi_init_from_param_vals(struct tspi_data *tspi_data,
				   struct key_mod_param_val *param_vals,
				   uint32_t num_param_vals)
{
	int uuid_set = 0;
	int i;
	int rc = 0;

	if (num_param_vals != tspi_num_params) {
		rc = -EINVAL;
		syslog(LOG_ERR, "Require [%d] param vals; got [%d]\n",
		       tspi_num_params, num_param_vals);
		goto out;
	}
	for (i = 0; i < num_param_vals; i++)
		tspi_params[i].val = &param_vals[i];
	memset(tspi_data, 0, sizeof(struct tspi_data));
	for (i = 0; i < num_param_vals; i++)
		if (strcmp(tspi_params[i].option, "tspi_uuid") == 0) {
			string_to_uuid(&tspi_data->uuid,
				       tspi_params[i].val->val);
			uuid_set = 1;
		}
	if (!uuid_set) {
		rc = -EINVAL;
		syslog(LOG_ERR, "uuid parameter must be set\n");
		goto out;
	}
out:
	return rc;
}

static int ecryptfs_tspi_get_blob(unsigned char *blob, size_t *blob_size,
				  struct key_mod_param_val *param_vals,
				  uint32_t num_param_vals)
{
	struct tspi_data tspi_data;
	int rc = 0;

	if ((rc = ecryptfs_tspi_init_from_param_vals(&tspi_data, param_vals,
						     num_param_vals))) {
		syslog(LOG_ERR, "Error parsing parameter values; rc = [%d]\n",
		       rc);
		goto out;
	}
	if (blob == NULL) {
		if ((rc = ecryptfs_tspi_serialize(NULL, blob_size,
						  &tspi_data))) {
			syslog(LOG_ERR, "Error serializing tspi; rc = [%d]\n",
			       rc);
			goto out;
		}
		goto out;
	}
	if ((rc = ecryptfs_tspi_serialize(blob, blob_size, &tspi_data))) {
		syslog(LOG_ERR, "Error serializing tspi; rc = [%d]\n", rc);
		goto out;
	}
out:
	return rc;
}

static int ecryptfs_tspi_destroy(unsigned char *blob)
{
	return 0;
}

#define ECRYPTFS_TSPI_MAX_WAIT_FOR_END 5

static int ecryptfs_tspi_finalize(void)
{
	uint32_t retries = 0;
	struct ecryptfs_tspi_connect_ticket *ticket;
	int rc = 0;

	while (ptr_to_used_ticket_list_head
	       && (retries < ECRYPTFS_TSPI_MAX_WAIT_FOR_END)) {
		sleep(1);
		retries++;
	}
	if (retries == ECRYPTFS_TSPI_MAX_WAIT_FOR_END) {
		syslog(LOG_ERR, "%s: Stale TSPI tickets in used list; cannot "
		       "shut down cleanly\n", __FUNCTION__);
		rc = -EBUSY;
		goto out;
	}
	ticket = ptr_to_free_ticket_list_head;
	while (ticket) {
		struct ecryptfs_tspi_connect_ticket *next;

		pthread_mutex_lock(&ticket->lock);
		next = ticket->next;
		if (ticket->flags
		    & ECRYPTFS_TSPI_TICKET_CTX_INITIALIZED) {
			Tspi_Context_Close(ticket->tspi_ctx);
			ticket->flags &= ~ECRYPTFS_TSPI_TICKET_CTX_INITIALIZED;
		}
		pthread_mutex_unlock(&ticket->lock);
		ticket = next;
	}
out:
	return rc;
}

static struct ecryptfs_key_mod_ops ecryptfs_tspi_ops = {
	&ecryptfs_tspi_init,
	NULL,
	NULL,
	&ecryptfs_tspi_get_params,
	NULL,
	&ecryptfs_tspi_get_blob,
	NULL,
	&ecryptfs_tspi_get_key_sig,
	NULL,
	&ecryptfs_tspi_encrypt,
	&ecryptfs_tspi_decrypt,
	&ecryptfs_tspi_destroy,
	&ecryptfs_tspi_finalize
};

struct ecryptfs_key_mod_ops *get_key_mod_ops(void)
{
	return &ecryptfs_tspi_ops;
}
