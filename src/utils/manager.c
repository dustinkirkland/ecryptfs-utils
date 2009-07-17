/**
 * Copyright (C) 2006 International Business Machines
 * Author(s): Trevor S. Highland <trevor.highland@gmail.com>
 *            Michael C. Thompson <mcthomps@us.ibm.com>
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
#include <getopt.h>
#include <sys/types.h>
#include <keyutils.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include "config.h"
#include "../include/ecryptfs.h"
#include "../include/decision_graph.h"
#include "io.h"

int main(int argc, char **argv)
{
	int quit, rc, selection;
	uint32_t version;
	char passphrase[ECRYPTFS_MAX_PASSWORD_LENGTH];
	char salt[ECRYPTFS_SALT_SIZE];
	struct ecryptfs_ctx ecryptfs_ctx;
	struct val_node *dummy_mnt_params;
	char auth_tok_sig[ECRYPTFS_SIG_SIZE_HEX+1];

	if ((rc = ecryptfs_validate_keyring())) {
		printf("Error attempting to validate keyring integrity; "
		       "rc = [%d]\n", rc);
		return 1;
	}
	memset(passphrase, 0, ECRYPTFS_MAX_PASSWORD_LENGTH);
	memset(salt, 0, ECRYPTFS_SALT_SIZE);
selection:
	quit = 0;
	selection = manager_menu();
	switch (selection) {
	case MME_MOUNT_PASSPHRASE:
		if ((rc = read_passphrase_salt(passphrase, salt)))
			goto out_wipe;
		if (!(*salt))
			memcpy(salt, common_salt, ECRYPTFS_SALT_SIZE);
		rc = ecryptfs_add_passphrase_key_to_keyring(auth_tok_sig,
							    passphrase, salt);
		if (rc == 1) {
			rc = 0;
			printf("\nThat key was already in the keyring.\n\n");
		} else if (!rc)
			printf("\nAdded key to keyring with signature [%s]."
			       "\n\n", auth_tok_sig);
		memset(passphrase, 0, ECRYPTFS_MAX_PASSWORD_LENGTH);
		memset(salt, 0, ECRYPTFS_SALT_SIZE);
		break;
	case MME_MOUNT_PUBKEY:
		if ((rc = ecryptfs_get_version(&version))) {
			printf("\nUnable to get the version number of the kernel\n");
			printf("module. Please make sure that you have the eCryptfs\n");
			printf("kernel module loaded, you have sysfs mounted, and\n");
			printf("the sysfs mount point is in /etc/mtab. This is\n");
			printf("necessary so that the mount helper knows which \n");
			printf("kernel options are supported.\n\n");
			printf("Make sure that your system is set up to auto-load\n"
			       "your filesystem kernel module on mount.\n\n");
			printf("Enabling passphrase-mode only for now.\n\n");
			version = ECRYPTFS_VERSIONING_PASSPHRASE;
		}
		ecryptfs_ctx.get_string = &get_string_stdin;
		if ((dummy_mnt_params = malloc(sizeof(struct val_node)))
		    == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		if ((rc = ecryptfs_process_decision_graph(
			     &ecryptfs_ctx, &dummy_mnt_params, version, "",
			     ECRYPTFS_KEY_MODULE_ONLY))) {
			printf("Error processing key generation decision graph;"
			       " rc = [%d]\n", rc);
			goto out;
		}
		if ((rc = ecryptfs_free_key_mod_list(&ecryptfs_ctx))) {
			printf("\nUnable to free key modules\n");
		}
		printf("Returning to main menu\n");
		break;
	case MME_GEN_PUBKEY:
		memset(&ecryptfs_ctx, 0, sizeof(struct ecryptfs_ctx));
		if ((rc = ecryptfs_get_version(&version))) {
			printf("\nUnable to get the version number of the kernel\n");
			printf("module. Please make sure that you have the eCryptfs\n");
			printf("kernel module loaded, you have sysfs mounted, and\n");
			printf("the sysfs mount point is in /etc/mtab. This is\n");
			printf("necessary so that the mount helper knows which \n");
			printf("kernel options are supported.\n\n");
			printf("Make sure that your system is set up to auto-load\n"
			       "your filesystem kernel module on mount.\n\n");
			printf("Enabling passphrase-mode only for now.\n\n");
			version = ECRYPTFS_VERSIONING_PASSPHRASE;
		}
		ecryptfs_ctx.get_string = &get_string_stdin;
		if ((rc = ecryptfs_process_key_gen_decision_graph(&ecryptfs_ctx,
								  version))) {
			printf("Error processing key generation decision graph;"
			       " rc = [%d]\n", rc);
			goto out;
		}
		if ((rc = ecryptfs_free_key_mod_list(&ecryptfs_ctx))) {
			printf("\nUnable to free key modules\n");
		}
		printf("Returning to main menu\n");
		goto selection;
	case MME_ABORT:
		quit = 1;
		goto out_wipe;
	default:
		fprintf(stderr, "Unknown option, aborting\n");
		quit = 1;
		rc = -1;
		goto out_wipe;
	}
out_wipe:
	memset(passphrase, 0, ECRYPTFS_MAX_PASSWORD_LENGTH);
	memset(salt, 0, ECRYPTFS_SALT_SIZE);
	if (!quit)
		goto selection;
out:
	if (selection == MME_MOUNT_PUBKEY || selection == MME_GEN_PUBKEY)
		rc = ecryptfs_free_key_mod_list(&ecryptfs_ctx);
	return rc;
}
