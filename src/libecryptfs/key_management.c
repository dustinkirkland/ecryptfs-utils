/**
 * Copyright (C) 2006 International Business Machines
 * Copyright (C) 2011 Gazzang, Inc
 * Author(s): Michael C. Thompson <mcthomps@us.ibm.com>
 *            Dustin Kirkland <dustin.kirkland@gazzang.com>
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
#include <errno.h>
#include <nss.h>
#include <pk11func.h>
#include <keyutils.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <fcntl.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <pwd.h>
#include "../include/ecryptfs.h"

#ifndef ENOKEY
#warning ENOKEY is not defined in your errno.h; setting it to 126
#define ENOKEY 126
#endif

/**
 * @auth_tok: (out) This function will allocate; callee must free
 * @auth_tok_sig: (out) Allocated memory this function fills in:
                        (ECRYPTFS_SIG_SIZE_HEX + 1)
 * @fekek: (out) Allocated memory this function fills in: ECRYPTFS_MAX_KEY_BYTES
 * @salt: (in) salt: ECRYPTFS_SALT_SIZE
 * @passphrase: (in) passphrase: ECRYPTFS_MAX_PASSPHRASE_BYTES
 */
int ecryptfs_generate_passphrase_auth_tok(struct ecryptfs_auth_tok **auth_tok,
					  char *auth_tok_sig, char *fekek,
					  char *salt, char *passphrase)
{
	int rc;

	*auth_tok = NULL;
	rc = generate_passphrase_sig(auth_tok_sig, fekek, salt, passphrase);
	if (rc) {
		syslog(LOG_ERR, "Error generating passphrase signature; "
		       "rc = [%d]\n", rc);
		rc = (rc < 0) ? rc : rc * -1;
		goto out;
	}
	*auth_tok = malloc(sizeof(struct ecryptfs_auth_tok));
	if (!*auth_tok) {
		syslog(LOG_ERR, "Unable to allocate memory for auth_tok\n");
		rc = -ENOMEM;
		goto out;
	}
	rc = generate_payload(*auth_tok, auth_tok_sig, salt, fekek);
	if (rc) {
		syslog(LOG_ERR, "Error generating payload for auth tok key; "
		       "rc = [%d]\n", rc);
		rc = (rc < 0) ? rc : rc * -1;
		goto out;
	}
out:
	return rc;
}

/**
 * ecryptfs_passphrase_sig_from_blob
 * @blob: Byte array of struct ecryptfs_auth_tok
 *
 * SWIG support function.
 */
binary_data ecryptfs_passphrase_sig_from_blob(char *blob)
{
	struct ecryptfs_auth_tok *auth_tok;
	binary_data bd;

	auth_tok = (struct ecryptfs_auth_tok *)blob;
	bd.size = (ECRYPTFS_PASSWORD_SIG_SIZE + 1);
	bd.data = auth_tok->token.password.signature;
	return bd;
}

/**
 * ecryptfs_passphrase_blob
 * @salt: Hexadecimal representation of the salt value
 * @passphrase: Passphrase
 *
 * SWIG support function.
 */
binary_data ecryptfs_passphrase_blob(char *salt, char *passphrase)
{
	unsigned char *blob;
	struct ecryptfs_auth_tok *auth_tok;
	char auth_tok_sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	char fekek[ECRYPTFS_MAX_KEY_BYTES];
	binary_data bd;
	int rc;

	memset(&bd, 0, sizeof(bd));
	rc = ecryptfs_generate_passphrase_auth_tok(&auth_tok, auth_tok_sig,
						   fekek, salt, passphrase);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to generate passphrase "
		       "authentication token blob; rc = [%d]\n", __FUNCTION__,
		       rc);
		blob = NULL;
		goto out;
	}
	blob = (unsigned char *)auth_tok;
	bd.size = sizeof(struct ecryptfs_auth_tok);
	bd.data = blob;
out:
	return bd;
}


int ecryptfs_remove_auth_tok_from_keyring(char *auth_tok_sig)
{
	int rc;

	rc = (int)keyctl_search(KEY_SPEC_USER_KEYRING, "user", auth_tok_sig, 0);
	if (rc < 0) {
		rc = errno;
		syslog(LOG_ERR, "Failed to find key with sig [%s]: %m\n",
		       auth_tok_sig);
		goto out;
	}
	rc = keyctl_unlink(rc, KEY_SPEC_USER_KEYRING);
	if (rc < 0) {
		rc = errno;
		syslog(LOG_ERR, "Failed to unlink key with sig [%s]: %s\n",
		       auth_tok_sig, strerror(rc));
		goto out;
	}
	rc = 0;
out:
	return rc;
}
int ecryptfs_add_auth_tok_to_keyring(struct ecryptfs_auth_tok *auth_tok,
				     char *auth_tok_sig)
{
	int rc;

	rc = (int)keyctl_search(KEY_SPEC_USER_KEYRING, "user", auth_tok_sig, 0);
	if (rc != -1) { /* we already have this key in keyring; we're done */
		rc = 1;
		goto out;
	} else if ((rc == -1) && (errno != ENOKEY)) {
		int errnum = errno;

		syslog(LOG_ERR, "keyctl_search failed: %m errno=[%d]\n",
		       errnum);
		rc = (errnum < 0) ? errnum : errnum * -1;
		goto out;
	}
	rc = add_key("user", auth_tok_sig, (void *)auth_tok,
		     sizeof(struct ecryptfs_auth_tok), KEY_SPEC_USER_KEYRING);
	if (rc == -1) {
		rc = -errno;
		syslog(LOG_ERR, "Error adding key with sig [%s]; rc = [%d] "
		       "\"%m\"\n", auth_tok_sig, rc);
		if (rc == -EDQUOT)
			syslog(LOG_WARNING, "Error adding key to keyring - keyring is full\n");
		goto out;
	}
	rc = 0;
out:
	return rc;
}

/**
 * ecryptfs_add_blob_to_keyring
 * @blob: Byte array containing struct ecryptfs_auth_tok
 * @sig: Hexadecimal representation of the auth tok signature
 *
 * SWIG support function.
 */
int ecryptfs_add_blob_to_keyring(char *blob, char *sig)
{
	int rc;

	rc = ecryptfs_add_auth_tok_to_keyring((struct ecryptfs_auth_tok *)blob,
					      sig);
	return rc;
}

/**
 * This is the common functionality used to put a password generated key into
 * the keyring, shared by both non-interactive and interactive signature
 * generation code.
 *
 * Returns 0 on add, 1 on pre-existed, negative on failure.
 */
int ecryptfs_add_passphrase_key_to_keyring(char *auth_tok_sig, char *passphrase,
					   char *salt)
{
	int rc;
	char fekek[ECRYPTFS_MAX_KEY_BYTES];
	struct ecryptfs_auth_tok *auth_tok = NULL;

	rc = ecryptfs_generate_passphrase_auth_tok(&auth_tok, auth_tok_sig,
						   fekek, salt, passphrase);
	if (rc) {
		syslog(LOG_ERR, "%s: Error attempting to generate the "
		       "passphrase auth tok payload; rc = [%d]\n",
		       __FUNCTION__, rc);
		goto out;
	}
	rc = ecryptfs_add_auth_tok_to_keyring(auth_tok, auth_tok_sig);
	if (rc < 0) {
		syslog(LOG_ERR, "%s: Error adding auth tok with sig [%s] to "
		       "the keyring; rc = [%d]\n", __FUNCTION__, auth_tok_sig,
		       rc);
		goto out;
	}
out:
	if (auth_tok) {
		memset(auth_tok, 0, sizeof(*auth_tok));
		free(auth_tok);
	}
	return rc;
}

int ecryptfs_wrap_passphrase_file(char *dest, char *wrapping_passphrase,
				  char *salt, char *src)
{
	int rc = 0;
	ssize_t size;
	int fd;
	int i;
	char *p = NULL;
	char decrypted_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES + 1];

	memset(decrypted_passphrase, 0, sizeof(decrypted_passphrase));
	if ((fd = open(src, O_RDONLY)) == -1) {
		syslog(LOG_ERR, "Error attempting to open [%s] for reading\n",
		       src);
		rc = -EIO;
		close(fd);
		goto out;
	}
	if ((size = read(fd, decrypted_passphrase,
			 ECRYPTFS_MAX_PASSPHRASE_BYTES)) <= 0) {
		syslog(LOG_ERR, "Error attempting to read encrypted "
		       "passphrase from file [%s]; size = [%zd]\n",
		       src, size);
                p = strrchr(decrypted_passphrase, '\n');
                if (p) *p = '\0';
		rc = -EIO;
		close(fd);
		goto out;
	}
	close(fd);
	if (ecryptfs_wrap_passphrase(dest, wrapping_passphrase, salt,
	    decrypted_passphrase) == 0) {
		unlink(src);
	} else {
		syslog(LOG_ERR, "Error attempting to wrap passphrase file "
			"[%s]-> [%s]\n", src, dest);
		rc = -EIO;
		goto out;
	}
out:
	return rc;
}

int ecryptfs_wrap_passphrase(char *filename, char *wrapping_passphrase,
			     char *wrapping_salt, char *decrypted_passphrase)
{
	char wrapping_auth_tok_sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	char wrapping_key[ECRYPTFS_MAX_KEY_BYTES];
	char padded_decrypted_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES +
		ECRYPTFS_AES_BLOCK_SIZE + 1];
	char encrypted_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES +
		ECRYPTFS_AES_BLOCK_SIZE + 1];
	int encrypted_passphrase_pos = 0;
	int decrypted_passphrase_pos = 0;
	int tmp1_outlen = 0;
	int tmp2_outlen = 0;
	SECStatus err;
	SECItem key_item;
	PK11SymKey *sym_key = NULL;
	PK11SlotInfo *slot = NULL;
	PK11Context *enc_ctx = NULL;
	SECItem *sec_param = NULL;
	int encrypted_passphrase_bytes;
	int decrypted_passphrase_bytes;
	int fd;
	ssize_t size;
	int rc;

	decrypted_passphrase_bytes = strlen(decrypted_passphrase);
	if (decrypted_passphrase_bytes > ECRYPTFS_MAX_PASSPHRASE_BYTES) {
		syslog(LOG_ERR, "Decrypted passphrase is [%d] bytes long; "
		       "[%d] is the max\n", decrypted_passphrase_bytes,
		       ECRYPTFS_MAX_PASSPHRASE_BYTES);
		rc = -EIO;
		goto out;
	}
	rc = generate_passphrase_sig(wrapping_auth_tok_sig, wrapping_key,
				     wrapping_salt, wrapping_passphrase);
	if (rc) {
		syslog(LOG_ERR, "Error generating passphrase signature; "
		       "rc = [%d]\n", rc);
		rc = (rc < 0) ? rc : rc * -1;
		goto out;
	}
	memset(padded_decrypted_passphrase, 0,
	       (ECRYPTFS_MAX_PASSPHRASE_BYTES + 1));
	memcpy(padded_decrypted_passphrase, decrypted_passphrase,
	       decrypted_passphrase_bytes);
	if ((decrypted_passphrase_bytes % ECRYPTFS_AES_BLOCK_SIZE) != 0)
		decrypted_passphrase_bytes += (ECRYPTFS_AES_BLOCK_SIZE
					       - (decrypted_passphrase_bytes
						  % ECRYPTFS_AES_BLOCK_SIZE));
	encrypted_passphrase_bytes = decrypted_passphrase_bytes;
	NSS_NoDB_Init(NULL);
	slot = PK11_GetBestSlot(CKM_AES_ECB, NULL);
	key_item.data = (unsigned char *)wrapping_key;
	key_item.len = ECRYPTFS_AES_KEY_BYTES;
	sym_key = PK11_ImportSymKey(slot, CKM_AES_ECB, PK11_OriginUnwrap,
				    CKA_ENCRYPT, &key_item, NULL);
	if (!sym_key) {
		syslog(LOG_ERR, "%s: PK11_ImportSymKey() returned NULL\n",
		       __FUNCTION__);
		rc = -EIO;
		goto out;
	}
	sec_param = PK11_ParamFromIV(CKM_AES_ECB, NULL);
	enc_ctx = PK11_CreateContextBySymKey(CKM_AES_ECB, CKA_ENCRYPT,
					     sym_key, sec_param);
	err = PK11_CipherOp(
		enc_ctx, (unsigned char *) encrypted_passphrase,
		&tmp1_outlen, ECRYPTFS_MAX_PASSPHRASE_BYTES +
		  ECRYPTFS_AES_BLOCK_SIZE,
		(unsigned char *) padded_decrypted_passphrase,
		decrypted_passphrase_bytes);//ECRYPTFS_MAX_PASSPHRASE_BYTES);
	if (err == SECFailure) {
		syslog(LOG_ERR, "%s: PK11_CipherOp() error; "
			"SECFailure = [%d]; PORT_GetError() = [%d]\n",
			__FUNCTION__, SECFailure, PORT_GetError());
		rc = - EIO;
		goto nss_finish;
	}
	err = PK11_DigestFinal(
		enc_ctx, 
		(unsigned char *) encrypted_passphrase + tmp1_outlen,
		(unsigned int *) &tmp2_outlen,
		(ECRYPTFS_MAX_PASSPHRASE_BYTES + 
		  ECRYPTFS_AES_BLOCK_SIZE - tmp1_outlen));
	if (err == SECFailure) {
		syslog(LOG_ERR, "%s: PK11 error on digest final; "
			"SECFailure = [%d]; PORT_GetError() = [%d]\n",
			__FUNCTION__, SECFailure, PORT_GetError());
		rc = - EIO;
	}

nss_finish:
	if (enc_ctx)
		PK11_DestroyContext(enc_ctx, PR_TRUE);
	if (sym_key)
		PK11_FreeSymKey(sym_key);
	if (sec_param)
		SECITEM_FreeItem(sec_param, PR_TRUE);
	if (slot)
		PK11_FreeSlot(slot);
	if (rc)
		goto out;
	encrypted_passphrase_pos += tmp1_outlen + tmp2_outlen;
	decrypted_passphrase_pos += tmp1_outlen + tmp2_outlen;
	decrypted_passphrase_bytes -= tmp1_outlen + tmp2_outlen;
	if (decrypted_passphrase_bytes != 0) {
		syslog(LOG_ERR, "Wrong size of wrapped passphrase\n");
		rc = - EIO;
		goto out;
	}
	unlink(filename);
	if ((fd = open(filename, (O_WRONLY | O_CREAT | O_EXCL),
		       (S_IRUSR | S_IWUSR))) == -1) {
		syslog(LOG_ERR, "Error attempting to open [%s] for writing\n",
		       filename);
		rc = -EIO;
		goto out;
	}
	if ((size = write(fd, wrapping_auth_tok_sig,
			  ECRYPTFS_SIG_SIZE_HEX)) <= 0) {
		syslog(LOG_ERR, "Error attempting to write encrypted "
		       "passphrase ([%d] bytes) to file [%s]; size = [%zu]\n",
		       encrypted_passphrase_bytes, filename, size);
		rc = -EIO;
		close(fd);
		goto out;
	}
	if ((size = write(fd, encrypted_passphrase,
			  encrypted_passphrase_bytes)) <= 0) {
		syslog(LOG_ERR, "Error attempting to write encrypted "
		       "passphrase ([%d] bytes) to file [%s]; size = [%zu]\n",
		       encrypted_passphrase_bytes, filename, size);
		rc = -EIO;
		close(fd);
		goto out;
	}
	close(fd);
	rc = 0;
out:
	return rc;
}

/**
 * decryptfs_passphrase must be able to hold
 * ECRYPTFS_MAX_PASSPHRASE_BYTES + 1 bytes
 */
int ecryptfs_unwrap_passphrase(char *decrypted_passphrase, char *filename,
			       char *wrapping_passphrase, char *wrapping_salt)
{
	char wrapping_auth_tok_sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	char wrapping_auth_tok_sig_from_file[ECRYPTFS_SIG_SIZE_HEX + 1];
	char wrapping_key[ECRYPTFS_MAX_KEY_BYTES];
	char encrypted_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES + 1];
	int encrypted_passphrase_pos = 0;
	int decrypted_passphrase_pos = 0;
	int tmp1_outlen = 0;
	int tmp2_outlen = 0;
	SECStatus err;
	SECItem key_item;
	PK11SymKey *sym_key = NULL;
	PK11SlotInfo *slot = NULL;
	PK11Context *enc_ctx = NULL;
	SECItem *sec_param = NULL;
	int encrypted_passphrase_bytes;
	int fd;
	ssize_t size;
	int rc;

	memset(wrapping_auth_tok_sig_from_file, 0,
	       sizeof(wrapping_auth_tok_sig_from_file));
	memset(encrypted_passphrase, 0, sizeof(encrypted_passphrase));
	rc = generate_passphrase_sig(wrapping_auth_tok_sig, wrapping_key,
				     wrapping_salt, wrapping_passphrase);
	if (rc) {
		syslog(LOG_ERR, "Error generating passphrase signature; "
		       "rc = [%d]\n", rc);
		rc = (rc < 0) ? rc : rc * -1;
		goto out;
	}
	if ((fd = open(filename, O_RDONLY)) == -1) {
		syslog(LOG_ERR, "Error attempting to open [%s] for reading\n",
		       filename);
		rc = -EIO;
		goto out;
	}
	if ((size = read(fd, wrapping_auth_tok_sig_from_file,
			 ECRYPTFS_SIG_SIZE_HEX)) <= 0) {
		syslog(LOG_ERR, "Error attempting to read encrypted "
		       "passphrase from file [%s]; size = [%zu]\n",
		       filename, size);
		rc = -EIO;
		close(fd);
		goto out;
	}
	if ((size = read(fd, encrypted_passphrase,
			 ECRYPTFS_MAX_PASSPHRASE_BYTES)) <= 0) {
		syslog(LOG_ERR, "Error attempting to read encrypted "
		       "passphrase from file [%s]; size = [%zu]\n",
		       filename, size);
		rc = -EIO;
		close(fd);
		goto out;
	}
	close(fd);
	if (memcmp(wrapping_auth_tok_sig_from_file, wrapping_auth_tok_sig,
		   ECRYPTFS_SIG_SIZE_HEX) != 0) {
		syslog(LOG_ERR, "Incorrect wrapping key for file [%s]\n",
		       filename);
		rc = -EIO;
		goto out;
	}
	encrypted_passphrase_bytes = size;
	NSS_NoDB_Init(NULL);
	slot = PK11_GetBestSlot(CKM_AES_ECB, NULL);
	key_item.data = (unsigned char *)wrapping_key;
	key_item.len = ECRYPTFS_AES_KEY_BYTES;
	sym_key = PK11_ImportSymKey(slot, CKM_AES_ECB, PK11_OriginUnwrap,
				    CKA_ENCRYPT, &key_item, NULL);
	if (!sym_key) {
		syslog(LOG_ERR, "%s: PK11_ImportSymKey() returned NULL\n",
		       __FUNCTION__);
		rc = -EIO;
		goto out;
	}
	sec_param = PK11_ParamFromIV(CKM_AES_ECB, NULL);
	enc_ctx = PK11_CreateContextBySymKey(CKM_AES_ECB, CKA_DECRYPT,
					     sym_key, sec_param);
	memset(decrypted_passphrase, 0, ECRYPTFS_MAX_PASSPHRASE_BYTES + 1);
	err = PK11_CipherOp(
		enc_ctx, (unsigned char *) decrypted_passphrase,
		&tmp1_outlen, ECRYPTFS_MAX_PASSPHRASE_BYTES,
		(unsigned char *) encrypted_passphrase,
		encrypted_passphrase_bytes);//ECRYPTFS_MAX_PASSPHRASE_BYTES);
	if (err == SECFailure) {
		syslog(LOG_ERR, "%s: PK11_CipherOp() error; "
			"SECFailure = [%d]; PORT_GetError() = [%d]\n",
			__FUNCTION__, SECFailure, PORT_GetError());
		rc = - EIO;
		goto nss_finish;
	}
	err = PK11_DigestFinal(
		enc_ctx, 
		(unsigned char *) decrypted_passphrase + tmp1_outlen,
		(unsigned int *) &tmp2_outlen,
		(ECRYPTFS_MAX_PASSPHRASE_BYTES - tmp1_outlen));
	if (err == SECFailure) {
		syslog(LOG_ERR, "%s: PK11 error on digest final; "
			"SECFailure = [%d]; PORT_GetError() = [%d]\n",
			__FUNCTION__, SECFailure, PORT_GetError());
		rc = - EIO;
	}

nss_finish:
	if (enc_ctx)
		PK11_DestroyContext(enc_ctx, PR_TRUE);
	if (sym_key)
		PK11_FreeSymKey(sym_key);
	if (sec_param)
		SECITEM_FreeItem(sec_param, PR_TRUE);
	if (slot)
		PK11_FreeSlot(slot);
	if (rc)
		goto out;
	encrypted_passphrase_pos += tmp1_outlen + tmp2_outlen;
	decrypted_passphrase_pos += tmp1_outlen + tmp2_outlen;
	encrypted_passphrase_bytes -= tmp1_outlen + tmp2_outlen;
	if (encrypted_passphrase_bytes != 0) {
		syslog(LOG_ERR, "Wrong size of unwrapped passphrase\n");
		rc = - EIO;
		goto out;
	}
out:
	return rc;
}

/**
 * ecryptfs_insert_wrapped_passphrase_into_keyring()
 *
 * Inserts two auth_tok objects into the user session keyring: a
 * wrapping passphrase auth_tok and the unwrapped passphrase auth_tok.
 *
 * Returns the signature of the wrapped passphrase that is inserted
 * into the user session keyring.
 */
int ecryptfs_insert_wrapped_passphrase_into_keyring(
	char *auth_tok_sig, char *filename, char *wrapping_passphrase,
	char *salt)
{
	char decrypted_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES + 1] ;
	int rc = 0;

	if ((rc = ecryptfs_unwrap_passphrase(decrypted_passphrase, filename,
					     wrapping_passphrase, salt))) {
		syslog(LOG_ERR, "Error attempting to unwrap passphrase from "
		       "file [%s]; rc = [%d]\n", filename, rc);
		rc = -EIO;
		goto out;
	}
	if ((rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig,
					decrypted_passphrase,
					ECRYPTFS_DEFAULT_SALT_FNEK_HEX)) < 0) {
		syslog(LOG_ERR, "Error attempting to add filename encryption "
		       "key to user session keyring; rc = [%d]\n", rc);
		goto out;
	}
	if ((rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig,
							 decrypted_passphrase,
							 salt)) < 0) {
		syslog(LOG_ERR, "Error attempting to add passphrase key to "
		       "user session keyring; rc = [%d]\n", rc);
	}
out:
	return rc;
}

/**
 * ecryptfs_add_key_module_key_to_keyring
 * @auth_tok_sig: (ECRYPTFS_SIG_SIZE_HEX + 1) bytes of allocated
 *                memory into which this function will write the
 *                expanded-hex key signature for the given key
 *                module
 * @key_mod: Key module handle
 *
 * Inserts a key module key blob into the keyring, using the
 * auth_tok_sig as the key signature.
 *
 * Returns =0 on successful addition, =1 if the key is already in the
 * keyring, and <0 on failure.
 */
int
ecryptfs_add_key_module_key_to_keyring(char *auth_tok_sig,
				       struct ecryptfs_key_mod *key_mod)
{
	size_t blob_size;
	struct ecryptfs_auth_tok *auth_tok = NULL;
	int rc;

	if (key_mod->blob == NULL) {
		if ((rc = (key_mod->ops->get_blob)(NULL, &blob_size,
						   key_mod->param_vals,
						   key_mod->num_param_vals))) {
			syslog(LOG_ERR, "Error attempting to get blob from "
			       "key module; rc = [%d]\n", rc);
			goto out;
		}
	} else {
		blob_size = key_mod->blob_size;
	}
	if ((auth_tok = malloc(sizeof(struct ecryptfs_auth_tok) + blob_size))
	    == NULL) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = ecryptfs_generate_key_payload(auth_tok, key_mod, auth_tok_sig,
						blob_size))) {
		syslog(LOG_ERR, "Error initializing key from module; "
		       "rc = [%d]\n", rc);
		goto out;
	}
	rc = (int)keyctl_search(KEY_SPEC_USER_KEYRING, "user", auth_tok_sig, 0);
	if (rc != -1) { /* we already have this key in keyring; we're done */
		rc = 1;
		goto out;
	}
	rc = add_key("user", auth_tok_sig, (void *)auth_tok,
		     (sizeof(struct ecryptfs_auth_tok) + blob_size),
		     KEY_SPEC_USER_KEYRING);
	if (rc < 0) {
		rc = -errno;
		syslog(LOG_ERR, "Error adding key with sig [%s]; rc ="
		       " [%d]\n", auth_tok_sig, rc);
		if (rc == -EDQUOT)
			syslog(LOG_WARNING, "Error adding key to keyring - keyring is full\n");
	} else rc = 0;
out:
	if (auth_tok != NULL) {
		memset(auth_tok, 0, (sizeof(struct ecryptfs_auth_tok) + blob_size));
		free(auth_tok);
	}
	return rc;
}

int ecryptfs_read_salt_hex_from_rc(char *salt_hex)
{
	struct ecryptfs_name_val_pair nvp_list_head;
	struct ecryptfs_name_val_pair *nvp;
	int rc;

	memset(&nvp_list_head, 0, sizeof(struct ecryptfs_name_val_pair));
	rc = ecryptfs_parse_rc_file(&nvp_list_head);
	if (rc) {
		if (rc != -ENOENT && rc != -EACCES) {
			syslog(LOG_WARNING,
				"Error attempting to parse .ecryptfsrc file; "
				"rc = [%d]", rc);
		}
		goto out;
	}
	nvp = nvp_list_head.next;
	while (nvp) {
		if (strcmp(nvp->name, "salt") == 0) {
			int valsize;

			if (!nvp->value)
				goto next_iteration;
			valsize = strlen(nvp->value);
			if (valsize != ECRYPTFS_SALT_SIZE_HEX)
				goto next_iteration;
			memcpy(salt_hex, nvp->value, ECRYPTFS_SALT_SIZE_HEX);
			goto out_free;
		}
next_iteration:
		nvp = nvp->next;
	}
	rc = -EINVAL;
out_free:
	free_name_val_pairs(nvp_list_head.next);
out:
	return rc;
}

int ecryptfs_check_sig(char *auth_tok_sig, char *sig_cache_filename,
		       int *flags)
{
	int fd;
	char tmp[ECRYPTFS_SIG_SIZE_HEX + 1];
	ssize_t size;
	int rc = 0;

	memset(tmp, 0, sizeof(tmp));
	(*flags) &= ~ECRYPTFS_SIG_FLAG_NOENT;
	fd = open(sig_cache_filename, O_RDONLY);
	if (fd == -1) {
		(*flags) |= ECRYPTFS_SIG_FLAG_NOENT;
		goto out;
	}
	while ((size = read(fd, tmp, (ECRYPTFS_SIG_SIZE_HEX + 1)))
	       == (ECRYPTFS_SIG_SIZE_HEX + 1)) {
		if (memcmp(auth_tok_sig, tmp, ECRYPTFS_SIG_SIZE_HEX)
		    == 0) {
			close(fd);
			goto out;
		}
		memset(tmp, 0, sizeof(tmp));
	}
	close(fd);
	(*flags) |= ECRYPTFS_SIG_FLAG_NOENT;
out:
	return rc;
}

int ecryptfs_append_sig(char *auth_tok_sig, char *sig_cache_filename)
{
	int fd;
	ssize_t size;
	char tmp[ECRYPTFS_SIG_SIZE_HEX + 1];
	int rc = 0;

	fd = open(sig_cache_filename, (O_WRONLY | O_CREAT),
		  (S_IRUSR | S_IWUSR));
	if (fd == -1) {
		syslog(LOG_ERR, "Open resulted in [%d]; [%m]\n", errno);
		rc = -EIO;
		goto out;
	}
	if (fchown(fd, getuid(), getgid()) == -1) {
		syslog(LOG_WARNING, "Can't change ownership of sig file; "
				    "errno = [%d]; [%m]\n", errno);
	}
	lseek(fd, 0, SEEK_END);
	memcpy(tmp, auth_tok_sig, ECRYPTFS_SIG_SIZE_HEX);
	tmp[ECRYPTFS_SIG_SIZE_HEX] = '\n';
	if ((size = write(fd, tmp, (ECRYPTFS_SIG_SIZE_HEX + 1))) !=
	    (ECRYPTFS_SIG_SIZE_HEX + 1)) {
		syslog(LOG_ERR, "Write of sig resulted in [%zu]; errno = [%d]; "
		       "[%m]\n", size, errno);
		rc = -EIO;
		close(fd);
		goto out;
	}
	close(fd);
out:
	return rc;
}

int ecryptfs_validate_keyring(void)
{
	long rc_long;
	int rc = 0;

	if ((rc_long = keyctl(KEYCTL_LINK, KEY_SPEC_USER_KEYRING,
			      KEY_SPEC_SESSION_KEYRING))) {
		syslog(LOG_ERR, "Error attempting to link the user session "
		       "keyring into the session keyring\n");
		rc = -EIO;
		goto out;
	}
out:
	return rc;
}

int ecryptfs_disable_echo(struct termios *saved_settings)
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

int ecryptfs_enable_echo(struct termios *saved_settings)
{
	return tcsetattr(0, TCSANOW, saved_settings);
}

char *ecryptfs_get_passphrase(char *prompt) {
	char *passphrase = NULL;
	char *p;
	struct termios current_settings;

	if ((passphrase =
	    (char *)malloc(ECRYPTFS_MAX_PASSWORD_LENGTH+2)) == NULL) {
		perror("malloc");
		printf("\n");
		return NULL;
	}
	if (prompt != NULL) {
		printf("%s: ", prompt);
	}
	ecryptfs_disable_echo(&current_settings);
	if (fgets(passphrase,
		  ECRYPTFS_MAX_PASSWORD_LENGTH+2, stdin) == NULL) {
		ecryptfs_enable_echo(&current_settings);
		printf("\n");
		free(passphrase);
		return NULL;
	}
	ecryptfs_enable_echo(&current_settings);
	p = strrchr(passphrase, '\n');
	if (p) *p = '\0';
	if (prompt != NULL)
		printf("\n");
	if (strlen(passphrase) > ECRYPTFS_MAX_PASSWORD_LENGTH) {
		fprintf(stderr,"Passphrase is too long. Use at most %u "
			       "characters long passphrase.\n",
			ECRYPTFS_MAX_PASSWORD_LENGTH);
		free(passphrase);
		return NULL;
	}
	return passphrase;
}

char *ecryptfs_get_wrapped_passphrase_filename() {
	struct passwd *pwd = NULL;
	struct stat s;
	char *filename = NULL;
	if ((pwd = getpwuid(getuid())) == NULL) {
		perror("getpwuid");
		return NULL;
	}
	if ((asprintf(&filename,
	    "%s/.ecryptfs/wrapped-passphrase", pwd->pw_dir) < 0)) {
		perror("asprintf");
		return NULL;
	}
	if (stat(filename, &s) != 0) {
		perror("stat");
		return NULL;
	}
	return filename;
}
