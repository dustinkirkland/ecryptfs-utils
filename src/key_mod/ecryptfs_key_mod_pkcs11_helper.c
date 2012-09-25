/**
 * Copyright (C) 2006-2007 International Business Machines Corp.
 * Author(s): Alon Bar-Lev <alon.barlev@gmail.com>, based on:
 *            Trevor S. Highland <trevor.highland@gmail.com>
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
#include <openssl/err.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pkcs11-helper-1.0/pkcs11h-certificate.h>
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"

struct pkcs11h_data {
	char *serialized_id;
	unsigned char *certificate_blob;
	size_t certificate_blob_size;
	char *passphrase;
};

struct pkcs11h_subgraph_key_ctx {
	struct ecryptfs_key_mod *key_mod;
	struct pkcs11h_data pkcs11h_data;
};

struct pkcs11h_subgraph_provider_ctx {
	struct ecryptfs_key_mod *key_mod;
	char *name;
	char *library;
	int allow_protected_authentication;
	int certificate_is_private;
	unsigned private_mask;
};

#if OPENSSL_VERSION_NUMBER < 0x00908000L
typedef unsigned char *__pkcs11_openssl_d2i_t;
#else
typedef const unsigned char *__pkcs11_openssl_d2i_t;
#endif

/**
 * ecryptfs_pkcs11h_deserialize
 * @pkcs11h_data: The deserialized version of the key module data;
 *                internal components pointed to blob memory
 * @blob: The key module-specific state blob
 *
 */
static int ecryptfs_pkcs11h_deserialize(struct pkcs11h_data *pkcs11h_data,
					unsigned char *blob)
{
	size_t serialized_id_length;
	size_t passphrase_length;
	size_t i = 0;
	int rc;

	serialized_id_length = blob[i++] % 256;
	serialized_id_length += blob[i++] << 8;
	if (serialized_id_length == 0) {
		pkcs11h_data->serialized_id = NULL;
	}
	else {
		pkcs11h_data->serialized_id = blob + i;
		i += serialized_id_length;
	}
	pkcs11h_data->certificate_blob_size = blob[i++] % 256;
	pkcs11h_data->certificate_blob_size += blob[i++] << 8;
	if (pkcs11h_data->certificate_blob_size == 0) {
		pkcs11h_data->certificate_blob = NULL;
	}
	else {
		pkcs11h_data->certificate_blob = blob + i;
		i += pkcs11h_data->certificate_blob_size;
	}
	passphrase_length = blob[i++] % 256;
	passphrase_length += blob[i++] << 8;
	if (passphrase_length == 0) {
		pkcs11h_data->passphrase = NULL;
	}
	else {
		pkcs11h_data->passphrase = blob + i;
		i += passphrase_length;
	}

	rc = 0;
out:
	return rc;
}

/**
 * @blob: Callee allocates this memory
 */
static int ecryptfs_pkcs11h_serialize(unsigned char *blob, size_t *blob_size,
				      struct pkcs11h_data *pkcs11h_data)
{
#define PUSHSER1(x) do { if (blob) { blob[i] = x; } i++; } while (0)
#define PUSHSERN(x,s) do { if (blob) { memcpy(&blob[i], x, s); } i+=s; } while (0)
	size_t serialized_id_length;
	size_t passphrase_length;
	size_t i = 0;
	int rc = 0;

	(*blob_size) = 0;
	if (!pkcs11h_data->serialized_id) {
		rc = -EINVAL;
		syslog(LOG_ERR, "PKCS#11: pkcs11h_data internal structure not properly filled in\n");
		goto out;
	}
	serialized_id_length = strlen(pkcs11h_data->serialized_id) + 1; /* + '\0' */
	PUSHSER1(serialized_id_length % 256);
	PUSHSER1(serialized_id_length >> 8);
	PUSHSERN(pkcs11h_data->serialized_id, serialized_id_length);
	PUSHSER1(pkcs11h_data->certificate_blob_size % 256);
	PUSHSER1(pkcs11h_data->certificate_blob_size >> 8);
	PUSHSERN(pkcs11h_data->certificate_blob, pkcs11h_data->certificate_blob_size);
	passphrase_length = strlen(pkcs11h_data->passphrase) + 1; /* + '\0' */
	PUSHSER1(passphrase_length % 256);
	PUSHSER1(passphrase_length >> 8);
	PUSHSERN(pkcs11h_data->passphrase, passphrase_length);
	(*blob_size) = i;
out:
	return rc;
#undef PUSHSER1
#undef PUSHSERN
}

static
void
pkcs11h_log (
	void * const global_data,
	unsigned flags,
	const char * const format,
	va_list args
) {
	vsyslog(LOG_INFO, format, args);
}

static
PKCS11H_BOOL
pkcs11h_token_prompt (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry
) {
	(void)global_data;
	(void)user_data;
	(void)retry;

	return FALSE;
}

static
PKCS11H_BOOL
pkcs11h_pin_prompt (
	void * const global_data,
	void * const user_data,
	const pkcs11h_token_id_t token,
	const unsigned retry,
	char * const pin,
	const size_t pin_max
) {
	char *prompt = NULL;
	int use_static_password = 0;
	int rc;

	(void)global_data;

	if (asprintf (&prompt, "Please enter PIN for token '%s'", token->display) == -1) {
		rc = -ENOMEM;
		goto out;
	}

	/* TEMP TEMP TEMP - BEGIN
	 * Until we can affect ecryptfs context via daemon */
	if (cryptfs_get_ctx_opts ()->prompt) {
		rc = cryptfs_get_ctx_opts ()->prompt ("password", prompt, pin, pin_max);
		if (rc == -EINVAL) {
			use_static_password = 1;
		}
		else {
			goto out;
		}
	}
	else {
		use_static_password = 1;
	}

	if (use_static_password) {
		if (retry != 0 || user_data == NULL) {
			rc = -EIO;
			goto out;
		}
		strncpy (pin, (char *)user_data, pin_max-1);
		pin[pin_max-1] = '\x0';
	}

	rc = 0;

	/* TEMP TEMP TEMP - END */
out:

	if (prompt != NULL) {
		free (prompt);
	}

	return rc == 0;
}

/**
 * ecryptfs_pkcs11h_get_public_key
 * @rsa: RSA key to allocate
 * @blob: Key module data to use in finding the key
 */
static int ecryptfs_pkcs11h_get_public_key(RSA **rsa, unsigned char *blob)
{
	struct pkcs11h_data _pkcs11h_data;
	struct pkcs11h_data *pkcs11h_data = &_pkcs11h_data;
	X509 *x509 = NULL;
	EVP_PKEY *pubkey = NULL;
	__pkcs11_openssl_d2i_t d2i1 = NULL;
	int rc;

	if ((rc = ecryptfs_pkcs11h_deserialize(pkcs11h_data, blob)) != 0) {
		goto out;
	}

	if ((x509 = X509_new ()) == NULL) {
		syslog(LOG_ERR, "PKCS#11: Unable to allocate certificate object");
		rc = -ENOMEM;
		goto out;
	}

	d2i1 = (__pkcs11_openssl_d2i_t)pkcs11h_data->certificate_blob;
	if (!d2i_X509 (&x509, &d2i1, pkcs11h_data->certificate_blob_size)) {
		syslog(LOG_ERR, "PKCS#11: Unable to parse X.509 certificate");
		rc = -EIO;
		goto out;
	}

	if ((pubkey = X509_get_pubkey(x509)) == NULL) {
		syslog(LOG_ERR, "PKCS#11: Cannot get public key");
		rc = -EIO;
		goto out;
	}
	
	if (pubkey->type != EVP_PKEY_RSA) {
		syslog(LOG_ERR, "PKCS#11: Invalid public key algorithm");
		rc = -EIO;
		goto out;
	}

	if (
		(*rsa = EVP_PKEY_get1_RSA(pubkey)) == NULL
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot get RSA key");
		rc = -EIO;
		goto out;
	}

	rc = 0;
out:
	if (pubkey != NULL) {
		EVP_PKEY_free(pubkey);
		pubkey = NULL;
	}

	if (x509 != NULL) {
		X509_free(x509);
		x509 = NULL;
	}

	return rc;
}

static int ecryptfs_pkcs11h_get_key_sig(unsigned char *sig, unsigned char *blob)
{
	RSA *rsa = NULL;
	int len, nbits, ebits, i;
	int nbytes, ebytes;
	char *hash = NULL;
	char *data = NULL;
	int rc;

	if ((rc = ecryptfs_pkcs11h_get_public_key(&rsa, blob))) {
		syslog(LOG_ERR, "PKCS#11: Error attempting to read RSA key from token; rc=[%d]\n", rc);
		goto out;
	}

	hash = malloc(SHA_DIGEST_LENGTH);
	if (!hash) {
		syslog(LOG_ERR, "PKCS#11: Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	nbits = BN_num_bits(rsa->n);
	nbytes = nbits / 8;
	if (nbits % 8)
		nbytes++;
	ebits = BN_num_bits(rsa->e);
	ebytes = ebits / 8;
	if (ebits % 8)
		ebytes++;
	len = 10 + nbytes + ebytes;
	data = malloc(3 + len);
	if (!data) {
		syslog(LOG_ERR, "PKCS#11: Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}
	i = 0;
	data[i++] = '\x99';
	data[i++] = (char)(len >> 8);
	data[i++] = (char)len;
	data[i++] = '\x04';
	data[i++] = '\00';
	data[i++] = '\00';
	data[i++] = '\00';
	data[i++] = '\00';
	data[i++] = '\02';
	data[i++] = (char)(nbits >> 8);
	data[i++] = (char)nbits;
	BN_bn2bin(rsa->n, &(data[i]));
	i += nbytes;
	data[i++] = (char)(ebits >> 8);
	data[i++] = (char)ebits;
	BN_bn2bin(rsa->e, &(data[i]));
	i += ebytes;
	SHA1(data, len + 3, hash);
	to_hex(sig, hash, ECRYPTFS_SIG_SIZE);
	sig[ECRYPTFS_SIG_SIZE_HEX] = '\0';

	rc = 0;
out:
	if (rc != 0) {
		syslog(LOG_ERR, "PKCS#11: Error attempting to generate key signature; rc=[%d]\n", rc);
	}

	if (data != NULL) {
		free(data);
		data = NULL;
	}
	if (hash != NULL) {
		free(hash);
		hash = NULL;
	}

	if (rsa != NULL) {
		RSA_free(rsa);
		rsa = NULL;
	}

	return rc;
}

/**
 * ecryptfs_pkcs11h_encrypt
 * @to: Where to write encrypted data
 * @size: Number of bytes to encrypt
 * @from: Data to encrypt
 * @blob: Arbitrary blob specific to this key module
 *
 * Encrypt @size bytes of data in @from, writing the encrypted data
 * into @to, using @blob as the parameters for the
 * encryption.
 */
static int ecryptfs_pkcs11h_encrypt(char *to, size_t *to_size, char *from,
				    size_t from_size, unsigned char *blob,
				    int blob_type)
{
	RSA *rsa = NULL;
	int rc;

	if (to == NULL) {
		*to_size = 0;
	}

	if ((rc = ecryptfs_pkcs11h_get_public_key(&rsa, blob))) {
		syslog(LOG_ERR, "PKCS#11: Error attempting to read RSA key from token; rc=[%d]\n", rc);
		goto out;
	}

	(*to_size) = RSA_size(rsa);
	if (to) {
		if (
			(rc = RSA_public_encrypt(
				from_size,
				from,
				to,
				rsa,
				RSA_PKCS1_PADDING
			)) == -1
		) {
			rc = -(int)ERR_get_error();
			syslog(LOG_ERR, "PKCS#11: Error attempting to perform RSA public key encryption; rc=[%d]\n", rc);
			goto out;
		}

		(*to_size) = rc;
	}

	rc = 0;
out:
	if (rsa != NULL) {
		RSA_free(rsa);
		rsa = NULL;
	}

	return rc;
}

/**
 * ecryptfs_pkcs11h_dencrypt
 * @from: Data to decrypt
 * @to: Where to write decrypted data
 * @decrypted_key_size: Number of bytes decrypted
 * @blob: Arbitrary blob specific to this key module
 *
 * Decrypt data in @from, writing the decrypted data into @to, using
 * @blob as the parameters for the encryption.
 */
static int ecryptfs_pkcs11h_decrypt(char *to, size_t *to_size, char *from,
				    size_t from_size, unsigned char *blob,
				    int blob_type)
{
	struct pkcs11h_data _pkcs11h_data;
	struct pkcs11h_data *pkcs11h_data = &_pkcs11h_data;
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_certificate_t certificate = NULL;
	CK_RV rv = CKR_OK;
	int rc;

	if (to == NULL) {
		*to_size = 0;
	}

	if ((rc = ecryptfs_pkcs11h_deserialize(pkcs11h_data, blob)) != 0) {
		goto out;
	}

	if (
		(rv = pkcs11h_certificate_deserializeCertificateId (
			&certificate_id,
			pkcs11h_data->serialized_id
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot deserialize id rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if (
		pkcs11h_data->certificate_blob != NULL &&
		(rv = pkcs11h_certificate_setCertificateIdCertificateBlob (
			certificate_id,
			pkcs11h_data->certificate_blob,
			pkcs11h_data->certificate_blob_size
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot set certificate blob rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if (
		(rv = pkcs11h_certificate_create (
			certificate_id,
			pkcs11h_data->passphrase,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&certificate
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot create certificate handle rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if (
		(rv = pkcs11h_certificate_decryptAny (
			certificate,
			CKM_RSA_PKCS,
			from,
			from_size,
			to,
			to_size
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot decrypt rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}


	/*
	 * As we cannot store context between
	 * calls, we must end PKCS#11 operation
	 * or token will fail with operation
	 * in progress.
	 */
	if (to == NULL) {
		char *tmp = (char *)malloc(*to_size);
		if (tmp == NULL) {
			rc = -ENOMEM;
			goto out;
		}

		pkcs11h_certificate_decryptAny (
			certificate,
			CKM_RSA_PKCS,
			from,
			from_size,
			tmp,
			to_size
		);

		free(tmp);
		tmp = NULL;
	}

	rc = 0;
out:
	if (certificate != NULL) {
		pkcs11h_certificate_freeCertificate (certificate);
		certificate = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}
	
	return rc;
}

static int pkcs11h_get_id_list (char **list) {
	pkcs11h_certificate_id_list_t user_certificates = NULL;
	pkcs11h_certificate_id_list_t current = NULL;
	CK_RV rv = CKR_FUNCTION_FAILED;
	char *s = NULL;
	int rc;

	*list = NULL;

	if (
		(rv = pkcs11h_certificate_enumCertificateIds (
			PKCS11H_ENUM_METHOD_CACHE_EXIST,
			NULL,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			NULL,
			&user_certificates
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot enumerate certificates rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto cleanup;
	}

	for (current = user_certificates; current != NULL; current = current->next) {
		pkcs11h_certificate_t certificate = NULL;
		X509 *x509 = NULL;
		BIO *bio = NULL;
		__pkcs11_openssl_d2i_t d2i1 = NULL;
		unsigned char *certificate_blob = NULL;
		size_t certificate_blob_size;
		char dn[1024] = {0};
		char serial[1024] = {0};
		char *ser = NULL;
		size_t ser_len = 0;
		int n;

		if (
			(rv = pkcs11h_certificate_serializeCertificateId (
				NULL,
				&ser_len,
				current->certificate_id
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot serialize certificate id certificates rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto cleanup1;
		}

		if (
			(ser = (char *)malloc (ser_len)) == NULL
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot allocate memory");
			rc = -ENOMEM;
			goto cleanup1;
		}

		if (
			(rv = pkcs11h_certificate_serializeCertificateId (
				ser,
				&ser_len,
				current->certificate_id
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot serialize certificate id certificates rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto cleanup1;
		}

		if (
			(rv = pkcs11h_certificate_create (
				current->certificate_id,
				NULL,
				PKCS11H_PROMPT_MASK_ALLOW_ALL,
				PKCS11H_PIN_CACHE_INFINITE,
				&certificate
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot create certificate rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto cleanup1;
		}

		if (
			(rv = pkcs11h_certificate_getCertificateBlob (
				certificate,
				NULL,
				&certificate_blob_size
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot load certificate rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto cleanup1;
		}

		certificate_blob = malloc(certificate_blob_size);
		if (!certificate_blob) {
			syslog(LOG_ERR, "Out of memory\n");
			rc = -ENOMEM;
			goto cleanup1;
		}

		if (
			(rv = pkcs11h_certificate_getCertificateBlob (
				certificate,
				certificate_blob,
				&certificate_blob_size
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot load certificate rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto cleanup1;
		}

		if ((x509 = X509_new ()) == NULL) {
			syslog(LOG_ERR, "PKCS#11: Unable to allocate certificate object");
			rc = -ENOMEM;
			goto cleanup1;
		}

		d2i1 = (__pkcs11_openssl_d2i_t)certificate_blob;
		if (!d2i_X509 (&x509, &d2i1, certificate_blob_size)) {
			syslog(LOG_ERR, "PKCS#11: Unable to parse X.509 certificate");
			rc = -EIO;
			goto cleanup1;
		}

		X509_NAME_oneline (
			X509_get_subject_name (x509),
			dn,
			sizeof(dn)
		);

		if ((bio = BIO_new (BIO_s_mem ())) == NULL) {
			syslog(LOG_ERR, "PKCS#11: Cannot create BIO");
			rc = -EIO;
			goto cleanup1;
		}

		i2a_ASN1_INTEGER(bio, X509_get_serialNumber (x509));
		n = BIO_read (bio, serial, sizeof(serial)-1);
		if (n<0) {
			serial[0] = '\x0';
		}
		else {
			serial[n] = 0;
		}

		{
			char *t = NULL;

			if (asprintf (&t, "%s%s (%s) [%s]\n", s!=NULL?s:"", dn, serial, ser) == -1) {
				rc = -ENOMEM;
				goto cleanup1;
			}
			if (s != NULL) {
				free(s);
			}
			s = t;
		}

	cleanup1:
		if (certificate_blob != NULL) {
			free(certificate_blob);
			certificate_blob = NULL;
		}

		if (x509 != NULL) {
			X509_free(x509);
			x509 = NULL;
		}

		if (bio != NULL) {
			BIO_free_all (bio);
			bio = NULL;
		}

		if (certificate != NULL) {
			pkcs11h_certificate_freeCertificate (certificate);
			certificate = NULL;
		}

		if (ser != NULL) {
			free(ser);
			ser = NULL;
		}
	}

	*list = s;
	s = NULL;
	rc = 0;

cleanup:

	if (user_certificates != NULL) {
		pkcs11h_certificate_freeCertificateIdList (user_certificates);
		user_certificates = NULL;
	}

	if (s != NULL) {
		free(s);
		s = NULL;
	}

	return rc;
}

static int ecryptfs_pkcs11h_process_key(struct pkcs11h_subgraph_key_ctx *subgraph_key_ctx,
			     struct val_node **mnt_params)
{
	struct pkcs11h_data *pkcs11h_data = &subgraph_key_ctx->pkcs11h_data;
	pkcs11h_certificate_id_t certificate_id = NULL;
	pkcs11h_certificate_t certificate = NULL;
	size_t blob_size;
	char *sig_mnt_opt;
	char sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	CK_RV rv;
	int rc;

	if (
		(rv = pkcs11h_certificate_deserializeCertificateId (
			&certificate_id,
			pkcs11h_data->serialized_id
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot deserialize id rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if (
		(rv = pkcs11h_certificate_create (
			certificate_id,
			pkcs11h_data->passphrase,
			PKCS11H_PROMPT_MASK_ALLOW_ALL,
			PKCS11H_PIN_CACHE_INFINITE,
			&certificate
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot get certificate rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if (pkcs11h_data->certificate_blob == NULL) {
		if (
			(rv = pkcs11h_certificate_getCertificateBlob (
				certificate,
				NULL,
				&pkcs11h_data->certificate_blob_size
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot load certificate rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto out;
		}

		pkcs11h_data->certificate_blob = malloc(pkcs11h_data->certificate_blob_size);
		if (!pkcs11h_data->certificate_blob) {
			syslog(LOG_ERR, "PKCS#11: Out of memory\n");
			rc = -ENOMEM;
			goto out;
		}

		if (
			(rv = pkcs11h_certificate_getCertificateBlob (
				certificate,
				pkcs11h_data->certificate_blob,
				&pkcs11h_data->certificate_blob_size
			)) != CKR_OK
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot load certificate rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
			rc = -EIO;
			goto out;
		}
	}

	if ((rc = ecryptfs_pkcs11h_serialize(NULL, &blob_size, 
					     pkcs11h_data))) {
		syslog(LOG_ERR, "PKCS#11: Error serializing pkcs11; rc=[%d]\n", rc);
		rc = MOUNT_ERROR;
		goto out;
	}
	if (blob_size == 0) {
		syslog(LOG_ERR, "PKCS#11: Error serializing pkcs11\n");
		rc = MOUNT_ERROR;
		goto out;
	}
	if ((subgraph_key_ctx->key_mod->blob = malloc(blob_size)) == NULL) {
		syslog(LOG_ERR, "PKCS#11: Out of memory\n");
		rc = MOUNT_ERROR;
		goto out;
	}
	if ((rc = ecryptfs_pkcs11h_serialize(subgraph_key_ctx->key_mod->blob,
					     &subgraph_key_ctx->key_mod->blob_size, 
					     pkcs11h_data))) {
		syslog(LOG_ERR, "PKCS#11: Error serializing pkcs11; rc=[%d]\n", rc);
		rc = MOUNT_ERROR;
		goto out;
	}
	if (subgraph_key_ctx->key_mod->blob_size != blob_size) {
		syslog(LOG_ERR, "PKCS#11: %s: Internal error\n", __FUNCTION__);
		exit(1);
	}
	if ((rc = ecryptfs_add_key_module_key_to_keyring(sig, subgraph_key_ctx->key_mod)) < 0) {
		syslog(
			LOG_ERR,
			"PKCS#11: Error attempting to add key to keyring for key module [%s]; rc=[%d]\n",
			subgraph_key_ctx->key_mod->alias,
			rc
		);
		rc = MOUNT_ERROR;
		goto out;
	}
	if ((rc = asprintf(&sig_mnt_opt, "ecryptfs_sig=%s", sig)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	stack_push(mnt_params, sig_mnt_opt);
out:
	if (certificate != NULL) {
		pkcs11h_certificate_freeCertificate (certificate);
		certificate = NULL;
	}

	if (certificate_id != NULL) {
		pkcs11h_certificate_freeCertificateId (certificate_id);
		certificate_id = NULL;
	}

	return rc;
}

static void
tf_ecryptfs_pkcs11h_destroy_subgraph_key_ctx(struct pkcs11h_subgraph_key_ctx *ctx)
{
	if (ctx->pkcs11h_data.serialized_id != NULL) {
		free(ctx->pkcs11h_data.serialized_id);
	}
	if (ctx->pkcs11h_data.passphrase != NULL) {
		memset(ctx->pkcs11h_data.passphrase, 0, strlen(ctx->pkcs11h_data.passphrase));
		free(ctx->pkcs11h_data.passphrase);
	}
	if (ctx->pkcs11h_data.certificate_blob != NULL) {
		free(ctx->pkcs11h_data.certificate_blob);
	}
	memset(&ctx->pkcs11h_data, 0, sizeof(ctx->pkcs11h_data));
	memset(ctx, 0, sizeof(*ctx));
}

static void
tf_ecryptfs_pkcs11h_destroy_subgraph_provider_ctx(struct pkcs11h_subgraph_provider_ctx *ctx)
{
	if (ctx->name != NULL) {
		free(ctx->name);
	}
	if (ctx->library != NULL) {
		free(ctx->library);
	}
	memset(ctx, 0, sizeof(*ctx));
}

static int tf_pkcs11h_global_loglevel(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	int rc;

	pkcs11h_setLogLevel (atoi (node->val));

	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_global_pincache(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	int rc;

	pkcs11h_setPINCachePeriod (atoi (node->val));

	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	int rc;

	if ((subgraph_provider_ctx = malloc(sizeof(*ctx)))
	    == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(subgraph_provider_ctx, 0, sizeof(*ctx));

	(*foo) = (void *)subgraph_provider_ctx;
	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider_name(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	int rc;

	subgraph_provider_ctx = (struct pkcs11h_subgraph_provider_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_provider_ctx->name, "%s", node->val))
	    == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider_library(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	int rc;

	subgraph_provider_ctx = (struct pkcs11h_subgraph_provider_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_provider_ctx->library, "%s", node->val))
	    == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider_prot_auth(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	int rc;

	subgraph_provider_ctx = (struct pkcs11h_subgraph_provider_ctx *)(*foo);
	sscanf (node->val, "%x", &subgraph_provider_ctx->allow_protected_authentication);
	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider_cert_private(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	int rc;

	subgraph_provider_ctx = (struct pkcs11h_subgraph_provider_ctx *)(*foo);
	sscanf (node->val, "%x", &subgraph_provider_ctx->certificate_is_private);
	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider_private_mask(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	int rc;

	subgraph_provider_ctx = (struct pkcs11h_subgraph_provider_ctx *)(*foo);
	sscanf (node->val, "%x", &subgraph_provider_ctx->private_mask);

	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_provider_end(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_provider_ctx *subgraph_provider_ctx;
	CK_RV rv = CKR_FUNCTION_FAILED;
	int rc;

	subgraph_provider_ctx = (struct pkcs11h_subgraph_provider_ctx *)(*foo);

	if (
		(rv = pkcs11h_addProvider (
			subgraph_provider_ctx->name,
			subgraph_provider_ctx->library,
			subgraph_provider_ctx->allow_protected_authentication != 0,
			subgraph_provider_ctx->private_mask,
			PKCS11H_SLOTEVENT_METHOD_AUTO,
			0,
			subgraph_provider_ctx->certificate_is_private != 0
		)) != CKR_OK
	) {
		syslog(LOG_ERR, "PKCS#11: Cannot initialize provider '%s' rv=[%ld-'%s']", subgraph_provider_ctx->name, rv, pkcs11h_getMessage (rv));
	}

	tf_ecryptfs_pkcs11h_destroy_subgraph_provider_ctx(subgraph_provider_ctx);
	free(subgraph_provider_ctx);
	*foo = NULL;
	rc = DEFAULT_TOK;
out:
	return rc;
}

static int tf_pkcs11h_key_id(struct ecryptfs_ctx *ctx, struct param_node *node,
		       struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_key_ctx *subgraph_key_ctx;
	int rc;

	subgraph_key_ctx = (struct pkcs11h_subgraph_key_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_key_ctx->pkcs11h_data.serialized_id, "%s", node->val))
	    == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = DEFAULT_TOK;
	node->val = NULL;
out:
	return rc;
}

static int tf_pkcs11h_key_passwd(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_key_ctx *subgraph_key_ctx;
	int rc;

	subgraph_key_ctx = (struct pkcs11h_subgraph_key_ctx *)(*foo);
	if ((rc = asprintf(&subgraph_key_ctx->pkcs11h_data.passphrase, "%s",
			   node->val)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	node->val = NULL;
	rc = DEFAULT_TOK;
out:
	return rc;
}

static int tf_pkcs11h_key_x509file(struct ecryptfs_ctx *ctx, struct param_node *node,
			 struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_key_ctx *subgraph_key_ctx;
	X509 *x509 = NULL;
	unsigned char *p = NULL;
	FILE *fp = NULL;
	int rc;

	subgraph_key_ctx = (struct pkcs11h_subgraph_key_ctx *)(*foo);

	if (node->val != NULL && strlen(node->val) > 0) {
		if ((fp = fopen (node->val, "r")) == NULL) {
			syslog(LOG_ERR, "PKCS#11: Cannot open file '%s'", node->val);
			rc = -errno;
			goto out;
		}

		if (
			!PEM_read_X509 (
				fp,
				&x509,
				NULL,
				0
			)
		) {
			x509 = NULL;
			syslog(LOG_ERR, "PKCS#11: Cannot read PEM from file '%s'", node->val);
			rc = -EIO;
			goto out;
		}

		if ((subgraph_key_ctx->pkcs11h_data.certificate_blob_size = i2d_X509 (x509, NULL)) < 0	) {
			syslog(LOG_ERR, "PKCS#11: Cannot read decode certificate");
			rc = -EIO;
			goto out;
		}

		if (
			(subgraph_key_ctx->pkcs11h_data.certificate_blob = (unsigned char *)malloc (
				subgraph_key_ctx->pkcs11h_data.certificate_blob_size
			)) == NULL
		) {
			syslog(LOG_ERR, "PKCS#11: Cannot allocate memory");
			rc = -ENOMEM;
			goto out;
		}

		/*
		 * i2d_X509 increments p!!!
		 */
		p = subgraph_key_ctx->pkcs11h_data.certificate_blob;

		if ((subgraph_key_ctx->pkcs11h_data.certificate_blob_size = i2d_X509 (x509, &p)) < 0) {
			syslog(LOG_ERR, "PKCS#11: Cannot read decode certificate");
			goto out;
		}
	}

	node->val = NULL;
	if ((rc = ecryptfs_pkcs11h_process_key(subgraph_key_ctx, mnt_params))) {
		syslog(LOG_ERR, "PKCS#11: Error processing PKCS#11 key; rc=[%d]", rc);
		goto out;
	}
	tf_ecryptfs_pkcs11h_destroy_subgraph_key_ctx(subgraph_key_ctx);
	free(subgraph_key_ctx);
	(*foo) = NULL;
	rc = DEFAULT_TOK;

out:

	if (x509 != NULL) {
		X509_free(x509);
		x509 = NULL;
	}

	if (fp != NULL) {
		fclose (fp);
		fp = NULL;
	}

	return rc;
}

#define PKCS11H_GLOBAL_TOK_LOGLEVEL 0
#define PKCS11H_GLOBAL_TOK_PINCACHE 1
static struct param_node pkcs11h_global_param_nodes[] = {

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"pkcs11-log-level"},
	 .prompt = "PKCS#11 Log Level",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "0",
	 .suggested_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_pkcs11h_global_loglevel}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"pkcs11-pin-cache-timeout"},
	 .prompt = "PKCS#11 Log Level",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "-1",
	 .suggested_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_pkcs11h_global_pincache}}},
};

#define PKCS11H_PROVIER_TOK_PROVIDER 0
#define PKCS11H_PROVIER_TOK_NAME 1
#define PKCS11H_PROVIER_TOK_LIBRARY 2
#define PKCS11H_PROVIER_TOK_PROT_AUTH 3
#define PKCS11H_PROVIER_TOK_CERT_PRIVATE 4
#define PKCS11H_PROVIER_TOK_PRIVATE_MASK 5
#define PKCS11H_PROVIER_TOK_END 6
static struct param_node pkcs11h_provider_param_nodes[] = {

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"pkcs11-provider"},
	 .prompt = "PKCS#11 Provider",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "",
	 .suggested_val = NULL,
	 .flags = DISPLAY_TRANSITION_NODE_VALS | ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "name",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_NAME],
		 .trans_func = tf_pkcs11h_provider}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"name"},
	 .prompt = "PKCS#11 Provider Alias",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "library",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_LIBRARY],
		 .trans_func = tf_pkcs11h_provider_name}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"library"},
	 .prompt = "PKCS#11 Library",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_PROT_AUTH],
		 .trans_func = tf_pkcs11h_provider_library}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"allow-protected-auth"},
	 .prompt = "Allow Protected Authentication",
	 .val_type = VAL_HEX,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "1",
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT  | ECRYPTFS_ALLOW_IMPLICIT_TRANSITION,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_CERT_PRIVATE],
		 .trans_func = tf_pkcs11h_provider_prot_auth}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"cert-private"},
	 .prompt = "Certificate is private object",
	 .val_type = VAL_HEX,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "0",
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_PRIVATE_MASK],
		 .trans_func = tf_pkcs11h_provider_cert_private}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"private-mask"},
	 .prompt = "Private Key Mask",
	 .val_type = VAL_HEX,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "0",
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_END],
		 .trans_func = tf_pkcs11h_provider_private_mask}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"dummy"},
	 .prompt = "",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "",
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = NULL,
		 .next_token = &pkcs11h_provider_param_nodes[PKCS11H_PROVIER_TOK_PROVIDER],
		 .trans_func = tf_pkcs11h_provider_end}}},
};

#define PKCS11H_KEY_TOK_TOK 0
#define PKCS11H_KEY_TOK_ID 1
#define PKCS11H_KEY_TOK_PASSWD 2
#define PKCS11H_KEY_TOK_PASS_ENV 3
#define PKCS11H_KEY_TOK_PASS_STDIN 4
#define PKCS11H_KEY_TOK_DEFAULT_PASS 5
#define PKCS11H_KEY_TOK_DEFAULT_X509_FILE 6
static struct param_node pkcs11h_key_param_nodes[] = {
	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"keyformat"},
	 .prompt = "Key format",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = "id",
	 .flags = ECRYPTFS_PARAM_FLAG_NO_VALUE,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = "PKCS#11 ID",
		 .next_token = &pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID],
		 .trans_func = NULL}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"id"},
	 .prompt = "PKCS#11 Serialized ID",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .suggested_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 4,
	 .tl = {{.val = "passwd",
		 .pretty_val = "",
		 .next_token = &pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_PASSWD],
		 .trans_func = tf_pkcs11h_key_id},
	 	{.val = "passenv",
		 .pretty_val = "Passphrase ENV",
		 .next_token = &pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_PASS_ENV],
		 .trans_func = tf_pkcs11h_key_id},
	 	{.val = "passstdin",
		 .pretty_val = "Passphrase STDIN",
		 .next_token = &pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_PASS_STDIN],
		 .trans_func = tf_pkcs11h_key_id},
	 	{.val = "default",
		 .pretty_val = "Passphrase (empty for interactive)",
		 .next_token = &pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_DEFAULT_PASS],
		 .trans_func = tf_pkcs11h_key_id}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"passwd"},
	 .prompt = "Passphrase (empty for interactive)",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_MASK_OUTPUT,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_pkcs11h_key_passwd}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"passenv"},
	 .prompt = "Passphrase (empty for interactive)",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_MASK_OUTPUT,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_pkcs11h_key_passwd}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"passstdin"},
	 .prompt = "Passphrase (empty for interactive)",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = VERIFY_VALUE | STDIN_REQUIRED,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_pkcs11h_key_passwd}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"defaultpass"},
	 .prompt = "Passphrase (empty for interactive)",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = STDIN_REQUIRED,
	 .num_transitions = 1,
	 .tl = {{.val = "default",
		 .pretty_val = "Optional X.509 Certificate PEM file",
		 .next_token = &pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_DEFAULT_X509_FILE],
		 .trans_func = tf_pkcs11h_key_passwd}}},

	{.num_mnt_opt_names = 1,
	 .mnt_opt_names = {"x509file"},
	 .prompt = "Optional X.509 Certificate PEM file",
	 .val_type = VAL_STR,
	 .val = NULL,
	 .display_opts = NULL,
	 .default_val = NULL,
	 .flags = ECRYPTFS_PARAM_FLAG_ECHO_INPUT,
	 .num_transitions = 1,
	 .tl = {{.val = NULL,
		 .pretty_val = NULL,
		 .next_token = NULL,
		 .trans_func = tf_pkcs11h_key_x509file}}},
};

/**
 * tf_pkcs11h_key_enter
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
static int tf_pkcs11h_key_enter(struct ecryptfs_ctx *ctx,
			    struct param_node *param_node,
			    struct val_node **mnt_params, void **foo)
{
	struct pkcs11h_subgraph_key_ctx *subgraph_key_ctx;
	int rc;

	if ((subgraph_key_ctx = malloc(sizeof(*ctx)))
	    == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	memset(subgraph_key_ctx, 0, sizeof(*ctx));
	if ((rc = ecryptfs_find_key_mod(&subgraph_key_ctx->key_mod, ctx,
					param_node->val))) {
		syslog(LOG_ERR, "PKCS#11: Cannot find key_mod for param_node with val = [%s]\n", param_node->val);
		goto out;
	}

	if (pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID].suggested_val) {
		free (pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID].suggested_val);
		pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID].suggested_val = NULL;
	}

	if (!strcmp (param_node->mnt_opt_names[0], "key")) {
		if ((rc = pkcs11h_get_id_list(&pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID].suggested_val)) != 0) {
			goto out;
		}
	}

	(*foo) = (void *)subgraph_key_ctx;
out:
	return rc;
}

struct transition_node pkcs11h_key_transition = {
	.val = "pkcs11-helper",
	.pretty_val = "PKCS#11 module using pkcs11-helper",
	.next_token = &(pkcs11h_key_param_nodes[0]),
	.trans_func = tf_pkcs11h_key_enter
};

static int ecryptfs_pkcs11h_get_param_subgraph_trans_node(
	struct transition_node **trans, uint32_t version)
{
	if ((version & ECRYPTFS_VERSIONING_PUBKEY) == 0)
		return -1;
	(*trans) = &pkcs11h_key_transition;
	return 0;
}

static int ecryptfs_pkcs11h_parse_file(struct param_node *param_nodes)
{
	struct ecryptfs_ctx _ctx;
	struct ecryptfs_ctx *ctx = &_ctx;
	struct ecryptfs_name_val_pair nvp_head;
	struct val_node *dummy_mnt_params;
	struct passwd *pw;
	char *rcfile_fullpath = NULL;
	int fd;
	int rc;

	if ((pw = getpwuid(getuid())) == NULL) {
		rc = -EIO;
		goto out;
	}

	if (asprintf(&rcfile_fullpath, "%s/.ecryptfsrc.pkcs11", pw->pw_dir) == -1) {
		rc = -ENOMEM;
		goto out;
	}

	if ((fd = open(rcfile_fullpath, O_RDONLY)) == -1) {
		rc = -errno;
		goto out;
	}

	memset(ctx, 0, sizeof(*ctx));
	memset(&nvp_head, 0, sizeof(nvp_head));

	if ((dummy_mnt_params = malloc(sizeof(*dummy_mnt_params))) == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	rc = parse_options_file(fd, &nvp_head);
	close(fd);

	if (ecryptfs_verbosity) {
		struct ecryptfs_name_val_pair *nvp_item = &nvp_head;

		while (nvp_item) {
			if (ecryptfs_verbosity)
				syslog(LOG_INFO, "PKCS#11: name = [%s]; value = [%s]\n",
				       nvp_item->name, nvp_item->value);
			nvp_item = nvp_item->next;
		}
	}
	ctx->nvp_head = &nvp_head;
	ecryptfs_eval_decision_graph(ctx, &dummy_mnt_params, param_nodes,
				     &nvp_head);

	rc = 0;
out:
	if (rcfile_fullpath != NULL) {
		free(rcfile_fullpath);
	}

	return rc;
}

static int ecryptfs_pkcs11h_init(char **alias)
{
	CK_RV rv = CKR_FUNCTION_FAILED;
	int rc = 0;

	if (asprintf(alias, "pkcs11-helper") == -1) {
		syslog(LOG_ERR, "PKCS#11: Out of memory\n");
		rc = -ENOMEM;
		goto out;
	}

	if ((rv = pkcs11h_initialize ()) != CKR_OK) {
		syslog(LOG_ERR, "PKCS#11: Cannot initialize rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if ((rv = pkcs11h_setLogHook (pkcs11h_log, NULL)) != CKR_OK) {
		syslog(LOG_ERR, "PKCS#11: Cannot set hooks rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	pkcs11h_setLogLevel (PKCS11H_LOG_QUIET);

	ecryptfs_pkcs11h_parse_file(pkcs11h_global_param_nodes);

	if ((rv = pkcs11h_setTokenPromptHook (pkcs11h_token_prompt, NULL)) != CKR_OK) {
		syslog(LOG_ERR, "PKCS#11: Cannot set hooks rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if ((rv = pkcs11h_setPINPromptHook (pkcs11h_pin_prompt, NULL)) != CKR_OK) {
		syslog(LOG_ERR, "PKCS#11: Cannot set hooks rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	if ((rv = pkcs11h_setProtectedAuthentication (1)) != CKR_OK) {
		syslog(LOG_ERR, "PKCS#11: Cannot set protected authentication mode rv=[%ld-'%s']", rv, pkcs11h_getMessage (rv));
		rc = -EIO;
		goto out;
	}

	ecryptfs_pkcs11h_parse_file(pkcs11h_provider_param_nodes);

	rc = 0;
out:
	return rc;
}

static int ecryptfs_pkcs11h_finalize(void)
{
	if (pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID].suggested_val)
		free(pkcs11h_key_param_nodes[PKCS11H_KEY_TOK_ID].suggested_val);
	pkcs11h_terminate ();
	return 0;
}

static struct ecryptfs_key_mod_ops ecryptfs_pkcs11h_ops = {
	.init = &ecryptfs_pkcs11h_init,
	.get_gen_key_params = NULL,
	.get_gen_key_subgraph_trans_node = NULL,
	.get_params = NULL,
	.get_param_subgraph_trans_node = &ecryptfs_pkcs11h_get_param_subgraph_trans_node,
	.get_blob = NULL,
	.get_key_data = NULL,
	.get_key_sig = &ecryptfs_pkcs11h_get_key_sig,
	.get_key_hint = NULL,
	.encrypt = &ecryptfs_pkcs11h_encrypt,
	.decrypt = &ecryptfs_pkcs11h_decrypt,
	.destroy = NULL,
	.finalize = &ecryptfs_pkcs11h_finalize
};

struct ecryptfs_key_mod_ops *get_key_mod_ops(void)
{
	return &ecryptfs_pkcs11h_ops;
}
