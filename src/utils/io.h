/**
 * Copyright (C) 2006 International Business Machines
 * Author(s): Michael C Thompson <mcthomps@us.ibm.com>
 *
 * I/O functions for mount helper header file
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

#include "ecryptfs.h"

int main_menu(uint32_t version);
int manager_menu(void);
int read_passphrase_salt(char *pass, char *salt);
int get_string_stdin(char **val, char *prompt, int echo);
void ecryptfs_get_crypto_modules(struct ecryptfs_cipher_elem *cipher_list_head,
			 	 struct cipher_str_name_map_elem* cipher_opt,
				 int *num_cipher_options, int max_cipher_opts,
				 int print);
int ecryptfs_verify_cipher(struct ecryptfs_cipher_elem *cipher_list_head,
			   char *cipher_name, int key_bytes);
int default_cipher(char **default_cipher, int *keysize,
		   struct ecryptfs_cipher_elem *cipher_list_head);
int
ecryptfs_select_crypto_module(struct ecryptfs_cipher_elem *cipher_list_head,
			      char **selected_cipher, int *keysize_bytes);
int ecryptfs_select_key_mod(struct ecryptfs_key_mod **key_mod,
			    struct ecryptfs_ctx *ctx);

int mygetchar();
