/**
 * Copyright (C) 2004-2006 International Business Machines
 * Written by Michael A. Halcrow <mhalcrow@us.ibm.com>
 * Modified by Michael C. Thompson <mcthomps@us.ibm.com>
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

#include <stdarg.h>
#ifdef USE_PRINTF
#include <stdio.h>
#else
#include <syslog.h>
#endif
#include "ecryptfs.h"

void PRINT(char *fmt, ...)
{
	va_list args;

	va_start(args, fmt);
#ifdef USE_PRINTF
	vfprintf(stdout, fmt, args);
#else
	syslog(LOG_NOTICE, fmt, args);
#endif
	va_end(args);
}

/**
 * Dump hexadecimal representation of char array
 *
 * @param data
 * @param bytes
 */
void dump_hex(char *data, int bytes)
{
	char buf[128];
	char tmp[8];
	int i = 0;
	int pretty_print = 1;
	buf[0] = '\0';
	if (bytes != 0) {
		sprintf(tmp, "0x%.2x.", (unsigned char)data[i]);
		strcat(buf, tmp);
		i++;
	}
	while (i < bytes) {
		sprintf(tmp, "0x%.2x.", (unsigned char)data[i]);
		strcat(buf, tmp);
		i++;
		if (i%16 == 0) {
			strcat(buf, "\n");
			pretty_print = 0;
		} else {
			pretty_print = 1;
		}
	}
	if (pretty_print) {
		strcat(buf, "\n");
	}
	PRINT("%s", buf);
}

void dump_auth_tok(struct ecryptfs_auth_tok *auth_tok)
{
	struct ecryptfs_password *password;

	PRINT("Auth tok at mem loc [%p]:\n", auth_tok);
	PRINT(" * instanceof = [%d]\n", auth_tok->instanceof);
	PRINT(" * instantiated = [%d]\n", auth_tok->instantiated);
	switch (auth_tok->instanceof) {
		char salt[ECRYPTFS_SALT_SIZE + 1];
		char sig[ECRYPTFS_SIG_SIZE_HEX + 1];
	case ECRYPTFS_PASSWORD:
		password = &(auth_tok->token.password);
		PRINT("eCryptfs Password:\n");
		PRINT(" * password = [%s]\n", password->password);
		PRINT(" * password_size = [%d]\n", password->password_size);
		PRINT(" * salt = ");
		dump_hex(password->salt, ECRYPTFS_SALT_SIZE);
		PRINT(" * saltless = [%d]\n", password->saltless);
		PRINT(" * signature = [%.*s]\n", ECRYPTFS_SIG_SIZE_HEX,
			password->signature);
		PRINT(" * hash algorithm = [%d]\n", password->hash_algo);
		PRINT(" * hash iterations = [%d]\n", password->hash_iterations);
		if (!password->session_key_encryption_key_set) {
			PRINT("Session key encryption key not set\n");
			goto skip_password_key;
		}
		PRINT(" * Session key encryption key set = [%d]\n",
			password->session_key_encryption_key_set);
                PRINT(" * Session key encryption key size = [0x%x]\n",
			password->session_key_encryption_key_size);
		PRINT(" * Key dump:\n" );
		dump_hex(password->session_key_encryption_key,
			password->session_key_encryption_key_size);
 skip_password_key:
		break;
	case ECRYPTFS_PRIVATE_KEY:
		PRINT(" * signature = [%.*s]\n", ECRYPTFS_SIG_SIZE_HEX,
			auth_tok->token.private_key.signature);
		break;
	default:
		PRINT(" * Unrecognized instanceof\n" );
	}
	PRINT(" * session_key.flags = [0x%x]\n",
		auth_tok->session_key.flags );
	PRINT("Contents of session_key field\n");
	if (auth_tok->session_key.flags
	    & ECRYPTFS_USERSPACE_SHOULD_TRY_TO_DECRYPT) {
		PRINT(" * Userspace decrypt request set\n" );
	}
	if (auth_tok->session_key.flags
	    & ECRYPTFS_USERSPACE_SHOULD_TRY_TO_ENCRYPT) {
		PRINT(" * Userspace encrypt request set\n" );
	}
	if (auth_tok->session_key.flags
	    & ECRYPTFS_CONTAINS_DECRYPTED_KEY) {
		PRINT(" * Contains decrypted key\n" );
		PRINT(" * session_key.decrypted_key_size = "
			"[0x%x]\n", auth_tok->session_key.decrypted_key_size );
		PRINT(" * Key dump:\n" );
		dump_hex( auth_tok->session_key.decrypted_key,
			ECRYPTFS_MAX_KEY_BYTES );
	}
	if (auth_tok->session_key.flags
	    & ECRYPTFS_CONTAINS_ENCRYPTED_KEY) {
		PRINT(" * Contains encrypted key\n" );
		PRINT(" * session_key.encrypted_key_size = "
			"[0x%x]\n", auth_tok->session_key.encrypted_key_size );
		PRINT(" * Key dump:\n" );
		dump_hex( auth_tok->session_key.encrypted_key,
			  ECRYPTFS_MAX_ENCRYPTED_KEY_BYTES );
	}
}
