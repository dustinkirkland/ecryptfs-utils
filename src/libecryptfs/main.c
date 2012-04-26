/**
 * Copyright (C) 2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *		Tyler Hicks <tyhicks@ou.edu>
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
#include <mntent.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <sys/mount.h>
#include <getopt.h>
#include <sys/types.h>
#include <keyutils.h>
#include <sys/ipc.h>
#include <sys/param.h>
#include <sys/shm.h>
#include <sys/sem.h>
#include "../include/ecryptfs.h"

int ecryptfs_verbosity = 0;

void ecryptfs_get_versions(int *major, int *minor, int *file_version)
{
	*major = ECRYPTFS_VERSION_MAJOR;
	*minor = ECRYPTFS_VERSION_MINOR;
	if (file_version)
		*file_version = ECRYPTFS_SUPPORTED_FILE_VERSION;
}

inline void to_hex(char *dst, char *src, int src_size)
{
	int x;

	for (x = 0; x < src_size; x++)
		sprintf(&dst[x*2], "%.2x", (unsigned char)src[x] );
	dst[src_size*2] = '\0';
}

void from_hex(char *dst, char *src, int dst_size)
{
        int x;
        char tmp[3] = { 0, };

        for (x = 0; x < dst_size; x++) {
                tmp[0] = src[x * 2];
                tmp[1] = src[x * 2 + 1];
                dst[x] = (char)strtol(tmp, NULL, 16);
        }
}

int do_hash(char *src, int src_size, char *dst, int algo)
{
	SECStatus err;

	NSS_NoDB_Init(NULL);
	err = PK11_HashBuf(algo, (unsigned char *)dst, (unsigned char *)src,
			   src_size);
	if (err == SECFailure) {
		syslog(LOG_ERR, "%s: PK11_HashBuf() error; SECFailure = [%d]; "
		       "PORT_GetError() = [%d]\n", __FUNCTION__, SECFailure,
		       PORT_GetError());
		err = -EINVAL;
		goto out;
	}
out:
	return (int)err;
}

/* Read ecryptfs private mount from file
 * Allocate and return a string
 */
char *ecryptfs_fetch_private_mnt(char *pw_dir) {
	char *mnt_file = NULL;
	char *mnt_default = NULL;
	char *mnt = NULL;
	FILE *fh = NULL;
	/* Construct mnt file name */
	if (asprintf(&mnt_default, "%s/%s", pw_dir, ECRYPTFS_PRIVATE_DIR) < 0
			|| mnt_default == NULL) {
		perror("asprintf");
		return NULL;
	}
	if (
			asprintf(&mnt_file, "%s/.ecryptfs/%s.mnt", pw_dir, ECRYPTFS_PRIVATE_DIR) < 0
			|| mnt_file == NULL) {
		perror("asprintf");
		return NULL;
	}
	fh = fopen(mnt_file, "r");
	if (fh == NULL) {
		mnt = mnt_default;
	} else {
		flockfile(fh);
		if ((mnt = (char *)malloc(MAXPATHLEN+1)) == NULL) {
			perror("malloc");
			return NULL;
		}
		if (fgets(mnt, MAXPATHLEN, fh) == NULL) {
			mnt = mnt_default;
		} else {
			/* Ensure that mnt doesn't contain newlines */
			mnt = strtok(mnt, "\n");
		}
		fclose(fh);
	}
	if (mnt_file != NULL)
		free(mnt_file);
	if (mnt_default != NULL && mnt != mnt_default)
		free(mnt_default);
	return mnt;
}


/* Check if an ecryptfs private device or mount point is mounted.
 * Return 1 if a filesystem in mtab matches dev && mnt && sig.
 * Return 0 otherwise.
 */
int ecryptfs_private_is_mounted(char *dev, char *mnt, char *sig, int mounting) {
	FILE *fh = NULL;
	struct mntent *m = NULL;
	char *opt = NULL;
	int mounted;
	if (sig && asprintf(&opt, "ecryptfs_sig=%s", sig) < 0) {
		perror("asprintf");
		return 0;
	}
	fh = setmntent("/proc/mounts", "r");
	if (fh == NULL) {
		perror("setmntent");
		return 0;
	}
	mounted = 0;
	flockfile(fh);
	while ((m = getmntent(fh)) != NULL) {
		if (strcmp(m->mnt_type, "ecryptfs") != 0)
			/* Skip if this entry is not an ecryptfs mount */
			continue;
		if (mounting == 1) {
			/* If mounting, return "already mounted" if EITHER the
 			 * dev or the mnt dir shows up in mtab/mounts;
 			 * regardless of the signature of such mounts;
 			 */
			if (dev != NULL && strcmp(m->mnt_fsname, dev) == 0) {
				mounted = 1;
				break;
			}
			if (mnt != NULL && strcmp(m->mnt_dir, mnt) == 0) {
				mounted = 1;
				break;
			}
		} else {
			/* Otherwise, we're unmounting, and we need to be
			 * very conservative in finding a perfect match
			 * to unmount.  The device, mountpoint, and signature
			 * must *all* match perfectly.
			 */
			if (
			    strcmp(m->mnt_fsname, dev) == 0 &&
			    strcmp(m->mnt_dir, mnt) == 0 &&
			    (!opt || hasmntopt(m, opt) != NULL)
			) {
				mounted = 1;
				break;
			}
		}
	}
	endmntent(fh);
	if (opt != NULL)
		free(opt);
	return mounted;
}


/**
 * TODO: We need to support more hash algs
 * @fekek: ECRYPTFS_MAX_KEY_BYTES bytes of allocated memory
 *
 * @passphrase A NULL-terminated char array
 *
 * @salt A salt
 *
 * @passphrase_sig An allocated char array into which the generated
 * signature is written; PASSWORD_SIG_SIZE bytes should be allocated
 *
 */
int
generate_passphrase_sig(char *passphrase_sig, char *fekek,
			char *salt, char *passphrase)
{
	char salt_and_passphrase[ECRYPTFS_MAX_PASSPHRASE_BYTES
				 + ECRYPTFS_SALT_SIZE];
	int passphrase_size;
	int alg = SEC_OID_SHA512;
	int dig_len = SHA512_DIGEST_LENGTH;
	char buf[SHA512_DIGEST_LENGTH];
	int hash_iterations = ECRYPTFS_DEFAULT_NUM_HASH_ITERATIONS;
	int rc = 0;

	passphrase_size = strlen(passphrase);
	if (passphrase_size > ECRYPTFS_MAX_PASSPHRASE_BYTES) {
		passphrase_sig = NULL;
		syslog(LOG_ERR, "Passphrase too large (%d bytes)\n",
		       passphrase_size);
		return -EINVAL;
	}
	memcpy(salt_and_passphrase, salt, ECRYPTFS_SALT_SIZE);
	memcpy((salt_and_passphrase + ECRYPTFS_SALT_SIZE), passphrase,
		passphrase_size);
	if ((rc = do_hash(salt_and_passphrase,
			  (ECRYPTFS_SALT_SIZE + passphrase_size), buf, alg))) {
		return rc;
	}
	hash_iterations--;
	while (hash_iterations--) {
		if ((rc = do_hash(buf, dig_len, buf, alg))) {
			return rc;
		}
	}
	memcpy(fekek, buf, ECRYPTFS_MAX_KEY_BYTES);
	if ((rc = do_hash(buf, dig_len, buf, alg))) {
		return rc;
	}
	to_hex(passphrase_sig, buf, ECRYPTFS_SIG_SIZE);
	return 0;
}

/**
 * @return Zero on success
 */
int
generate_payload(struct ecryptfs_auth_tok *auth_tok, char *passphrase_sig,
		 char *salt, char *session_key_encryption_key)
{
	int rc = 0;
	int major, minor;

	memset(auth_tok, 0, sizeof(struct ecryptfs_auth_tok));
	ecryptfs_get_versions(&major, &minor, NULL);
	auth_tok->version = (((uint16_t)(major << 8) & 0xFF00)
			     | ((uint16_t)minor & 0x00FF));
	auth_tok->token_type = ECRYPTFS_PASSWORD;
	strncpy((char *)auth_tok->token.password.signature, passphrase_sig,
		ECRYPTFS_PASSWORD_SIG_SIZE);
	memcpy(auth_tok->token.password.salt, salt, ECRYPTFS_SALT_SIZE);
	memcpy(auth_tok->token.password.session_key_encryption_key,
	       session_key_encryption_key, ECRYPTFS_MAX_KEY_BYTES);
	/* TODO: Make the hash parameterizable via policy */
	auth_tok->token.password.session_key_encryption_key_bytes =
		ECRYPTFS_MAX_KEY_BYTES;
	auth_tok->token.password.flags |=
		ECRYPTFS_SESSION_KEY_ENCRYPTION_KEY_SET;
	/* The kernel code will encrypt the session key. */
	auth_tok->session_key.encrypted_key[0] = 0;
	auth_tok->session_key.encrypted_key_size = 0;
	/* Default; subject to change by kernel eCryptfs */
	auth_tok->token.password.hash_algo = PGP_DIGEST_ALGO_SHA512;
	auth_tok->token.password.flags &= ~(ECRYPTFS_PERSISTENT_PASSWORD);
	return rc;
}

/**
 * @auth_tok: A previous call to get_blob() by the callee determined
 *            how much space to allocate at the end of the auth_tok
 *            memory for the blob; this memory is already allocated
 *            and ready to be written into
 */
int
ecryptfs_generate_key_payload(struct ecryptfs_auth_tok *auth_tok,
			      struct ecryptfs_key_mod *key_mod,
			      char *sig, size_t blob_size)
{
	int major, minor;
	unsigned char *key_data;
	size_t key_data_len;
	size_t blob_size_tmp;
	int rc = 0;

	memset(auth_tok, 0, sizeof(struct ecryptfs_auth_tok) + blob_size);
	ecryptfs_get_versions(&major, &minor, NULL);
	auth_tok->version = (((uint16_t)(major << 8) & 0xFF00)
			     | ((uint16_t)minor & 0x00FF));
	auth_tok->token_type = ECRYPTFS_PRIVATE_KEY;
	if (key_mod->blob == NULL) {
		if ((rc = (key_mod->ops->get_blob)
		     (auth_tok->token.private_key.data, &blob_size_tmp,
		      key_mod->param_vals, key_mod->num_param_vals))) {
			syslog(LOG_ERR, "Call into key module's get_blob "
			       "failed; rc = [%d]\n", rc);
			goto out;
		}
	} else {
		blob_size_tmp = key_mod->blob_size;
		memcpy(auth_tok->token.private_key.data, key_mod->blob,
		       key_mod->blob_size);
	}
	if (blob_size != blob_size_tmp) {
		rc = -EINVAL;
		syslog(LOG_ERR, "BUG: blob_size != blob_size_tmp; key module "
		       "is having a hard time getting the two to match between "
		       "get_blob() calls, and this has probably led to memory "
		       "corruption. Bombing out.\n");
		exit(1);
		goto out;
	}
	if ((rc = (key_mod->ops->get_key_data)
	     (NULL, &key_data_len, auth_tok->token.private_key.data))) {
		syslog(LOG_ERR, "Call into key module's get_key_data failed; "
		       "rc = [%d]\n", rc);
		goto out;
	}
	if (key_data_len == 0) {
		if ((rc = (key_mod->ops->get_key_sig)(
			     (unsigned char *)sig,
			     auth_tok->token.private_key.data))) {
			syslog(LOG_ERR, "Call into key module's get_key_sig "
			       "failed; rc = [%d]\n", rc);
			goto out;
		}
	} else {
		if ((key_data = malloc(key_data_len)) == NULL) {
			rc = -ENOMEM;
			goto out;
		}
		if ((rc = (key_mod->ops->get_key_data)
		     (key_data, &key_data_len,
		      auth_tok->token.private_key.data))) {
			syslog(LOG_ERR, "Call into key module's get_key_data "
			       "failed; rc = [%d]\n", rc);
			goto out;
		}
		if ((rc = ecryptfs_generate_sig_from_key_data(
			     (unsigned char *)sig, key_data, key_data_len))) {
			syslog(LOG_ERR, "Error attempting to generate "
			       "signature from key data; rc = [%d]\n", rc);
			goto out;
		}
		if (sig[0] == '\0') {
			if ((rc = (key_mod->ops->get_key_sig)(
				     (unsigned char *)sig,
				     auth_tok->token.private_key.data))) {
				syslog(LOG_ERR, "Call into key module's "
				       "get_key_sig failed; rc = [%d]\n", rc);
				goto out;
			}
		}
	}
	strncpy(auth_tok->token.private_key.key_mod_alias, key_mod->alias,
		ECRYPTFS_MAX_KEY_MOD_NAME_BYTES);
	/* TODO: Get rid of this */
	auth_tok->token.private_key.key_size = ECRYPTFS_MAX_KEY_MOD_NAME_BYTES;
	auth_tok->token.private_key.data_len = blob_size;
	memcpy(auth_tok->token.private_key.signature, sig,
	       ECRYPTFS_SIG_SIZE_HEX);
	auth_tok->token.private_key.signature[ECRYPTFS_SIG_SIZE_HEX] = '\0';
out:
	return rc;
}

static int zombie_semaphore_get(void)
{
	int sem_id;
	struct semid_ds semid_ds;
	struct sembuf sb;
	int i;
	int rc;

	sem_id = semget(ECRYPTFS_SEM_KEY, 1, (0666 | IPC_EXCL | IPC_CREAT));
	if (sem_id >= 0) {
		sb.sem_op = 1;
		sb.sem_flg = 0;
		sb.sem_num = 0;

		rc = semop(sem_id, &sb, 1);
		if (rc == -1) {
			semctl(sem_id, 0, IPC_RMID);
			syslog(LOG_ERR, "Error initializing semaphore\n");
			rc = -1;
			goto out;
		}
	} else if (errno == EEXIST) {
		int initialized = 0;

		sem_id = semget(ECRYPTFS_SEM_KEY, 1, 0);
		if (sem_id < 0) {
			syslog(LOG_ERR, "Error getting existing semaphore");
			rc = -1;
			goto out;
		}
#define RETRY_LIMIT 3
		for (i = 0; i < RETRY_LIMIT; i++) {
			semctl(sem_id, 0, IPC_STAT, &semid_ds);
			if (semid_ds.sem_otime != 0) {
				initialized = 1;
				break;
			} else
				sleep(1);
		}
		if (!initialized) {
			syslog(LOG_ERR, "Waited too long for initialized "
			       "semaphore; something's wrong\n");
			rc = -1;
			goto out;
		}
	} else {
		syslog(LOG_ERR, "Error attempting to get semaphore\n");
		rc = -1;
		goto out;
	}
	rc = sem_id;
out:
	return rc;
}

static void zombie_semaphore_lock(int sem_id)
{
	struct sembuf sb;
	int i;
	int rc;

	sb.sem_num = 0;
	sb.sem_op = -1;
	sb.sem_flg = IPC_NOWAIT;
	for (i = 0; i < RETRY_LIMIT; i++) {
		rc = semop(sem_id, &sb, 1);
		if (rc == -1 && errno == EAGAIN) {
			sleep(1);
		} else if (rc == -1) {
			syslog(LOG_ERR, "Error locking semaphore; errno "
			       "string = [%m]\n");
			goto out;
		} else
			goto out;
	}
	syslog(LOG_ERR, "Error locking semaphore; hit max retries\n");
out:
	return;
}

static void zombie_semaphore_unlock(int sem_id)
{
	struct sembuf sb;
	int rc;

	sb.sem_num = 0;
	sb.sem_op = 1;
	sb.sem_flg = 0;
	rc = semop(sem_id, &sb, 1);
	if (rc == -1) {
		syslog(LOG_ERR, "Error unlocking semaphore\n");
		goto out;
	}
out:
	return;
}

static int get_zombie_shared_mem_locked(int *shm_id, int *sem_id)
{
	int rc;
	
	(*sem_id) = zombie_semaphore_get();
	if ((*sem_id) == -1) {
		syslog(LOG_ERR, "Error attempting to get zombie semaphore\n");
		rc = -EIO;
		goto out;
	}
	zombie_semaphore_lock((*sem_id));
	rc = shmget(ECRYPTFS_SHM_KEY, ECRYPTFS_SHM_SIZE, (0666 | IPC_CREAT
							  | IPC_EXCL));
	if (rc == -1 && errno == EEXIST)
		rc = shmget(ECRYPTFS_SHM_KEY, ECRYPTFS_SHM_SIZE, 0);
	else {
		char *shm_virt;

		(*shm_id) = rc;
		shm_virt = shmat((*shm_id), NULL, 0);
		if (shm_virt == (void *)-1) {
			syslog(LOG_ERR, "Error attaching to newly allocated "
			       "shared memory; errno string = [%m]\n");
			rc = -EIO;
			zombie_semaphore_unlock((*sem_id));
			goto out;
		}
		memset(shm_virt, 0, ECRYPTFS_SHM_SIZE);
		if ((rc = shmdt(shm_virt))) {
			rc = -EIO;
			zombie_semaphore_unlock((*sem_id));
			goto out;
		}
		rc = shmget(ECRYPTFS_SHM_KEY, ECRYPTFS_SHM_SIZE, 0);
	}
	if (rc == -1) {
		syslog(LOG_ERR, "Error attempting to get identifier for "
		       "shared memory with key [0x%.8x]\n", ECRYPTFS_SHM_KEY);
		rc = -EIO;
		zombie_semaphore_unlock((*sem_id));
		goto out;
	}
	(*shm_id) = rc;
	rc = 0;
out:
	return rc;
}

static int list_pid_sid_pairs(int shm_id)
{
	pid_t sid_tmp;
	pid_t pid_tmp;
	char *shm_virt;
	int i;
	int rc;

	if (sizeof(pid_t) != sizeof(uint32_t)) {
		syslog(LOG_ERR, "sizeof(pid_t) != sizeof(uint32_t); the code "
		       "needs some tweaking to work on this architecture\n");
		rc = -EINVAL;
		goto out;
	}
	shm_virt = shmat(shm_id, NULL, 0);
	if (shm_virt == (void *)-1) {
		rc = -EIO;
		goto out;
	}
	i = 0;
	memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	sid_tmp = ntohl(sid_tmp); /* uint32_t */
	memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	pid_tmp = ntohl(pid_tmp); /* uint32_t */
	while (!(sid_tmp == 0 && pid_tmp == 0)) {
		if ((i + (2 * sizeof(pid_t))) > ECRYPTFS_SHM_SIZE)
			break;
		memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		sid_tmp = ntohl(sid_tmp); /* uint32_t */
		memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		pid_tmp = ntohl(pid_tmp); /* uint32_t */
	}
	if ((rc = shmdt(shm_virt)))
		rc = -EIO;
out:
	return rc;
}

static int find_pid_for_this_sid(pid_t *pid, int shm_id)
{
	pid_t sid_tmp;
	pid_t sid;
	pid_t pid_tmp;
	pid_t this_pid;
	char *shm_virt;
	int i;
	int rc;

	(*pid) = 0;
	if (sizeof(pid_t) != sizeof(uint32_t)) {
		syslog(LOG_ERR, "sizeof(pid_t) != sizeof(uint32_t); the code "
		       "needs some tweaking to work on this architecture\n");
		rc = -EINVAL;
		goto out;
	}
	shm_virt = shmat(shm_id, NULL, 0);
	if (shm_virt == (void *)-1) {
		rc = -EIO;
		goto out;
	}
	i = 0;
	memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	sid_tmp = ntohl(sid_tmp); /* uint32_t */
	memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	pid_tmp = ntohl(pid_tmp); /* uint32_t */
	this_pid = getpid();
	sid = getsid(this_pid);
	while (!(sid_tmp == 0 && pid_tmp == 0)) {
		if (sid_tmp == sid) {
			(*pid) = pid_tmp;
			goto end_search;
		}
		if ((i + (2 * sizeof(pid_t))) > ECRYPTFS_SHM_SIZE)
			break;
		memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		sid_tmp = ntohl(sid_tmp); /* uint32_t */
		memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		pid_tmp = ntohl(pid_tmp); /* uint32_t */
	}
end_search:
	if ((rc = shmdt(shm_virt))) {
		rc = -EIO;
		(*pid) = 0;
	}
out:
	return rc;
}

static int remove_pid_for_this_sid(int shm_id)
{
	pid_t sid_tmp;
	pid_t sid;
	pid_t pid_tmp;
	pid_t pid;
	pid_t this_pid;
	char *shm_virt;
	int i;
	int rc;

	pid = 0;
	if (sizeof(pid_t) != sizeof(uint32_t)) {
		syslog(LOG_ERR, "sizeof(pid_t) != sizeof(uint32_t); the code "
		       "needs some tweaking to work on this architecture\n");
		rc = -EINVAL;
		goto out;
	}
	shm_virt = shmat(shm_id, NULL, 0);
	if (shm_virt == (void *)-1) {
		rc = -EIO;
		goto out;
	}
	i = 0;
	memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	sid_tmp = ntohl(sid_tmp); /* uint32_t */
	memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	pid_tmp = ntohl(pid_tmp); /* uint32_t */
	this_pid = getpid();
	sid = getsid(this_pid);
	while (!(sid_tmp == 0 && pid_tmp == 0)) {
		if (sid_tmp == sid) {
			pid = pid_tmp;
			break;
		}
		if ((i + (2 * sizeof(pid_t))) > ECRYPTFS_SHM_SIZE)
			break;
		memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		sid_tmp = ntohl(sid_tmp); /* uint32_t */
		memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		pid_tmp = ntohl(pid_tmp); /* uint32_t */
	}
	if (pid != 0) {
		char *tmp;
		int remainder = (ECRYPTFS_SHM_SIZE - i);

		if (remainder != 0) {
			if ((tmp = malloc(remainder)) == NULL) {
				rc = -ENOMEM;
				shmdt(shm_virt);
				goto out;
			}
			memcpy(tmp, &shm_virt[i], remainder);
			i -= (2 * sizeof(pid_t));
			memcpy(&shm_virt[i], tmp, remainder);
			i += remainder;
		} else
			i -= (2 * sizeof(pid_t));
		memset(&shm_virt[i], 0, (2 * sizeof(pid_t)));
		if (remainder != 0)
			free(tmp);
	}
	if ((rc = shmdt(shm_virt)))
		rc = -EIO;
out:
	return rc;
}

static int add_sid_pid_pair_to_shm(int shm_id)
{
	pid_t sid_tmp;
	pid_t sid;
	pid_t pid_tmp;
	pid_t pid;
	char *shm_virt;
	int i;
	int rc;

	if (sizeof(pid_t) != sizeof(uint32_t)) {
		syslog(LOG_ERR, "sizeof(pid_t) != sizeof(uint32_t); the code "
		       "needs some tweaking to work on this architecture\n");
		rc = -EINVAL;
		goto out;
	}
	shm_virt = shmat(shm_id, NULL, 0);
	if (shm_virt == (void *)-1) {
		syslog(LOG_ERR, "Error attaching to shared memory; error "
		       "string = [%m]\n");
		shm_virt = shmat(shm_id, NULL, 0);
		if (shm_virt == (void *)-1) {
			syslog(LOG_ERR, "Error attaching to shared memory; error "
			       "string = [%m]\n");
			rc = -EIO;
			goto out;
		}
		rc = -EIO;
		goto out;
	}
	i = 0;
	memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	sid_tmp = ntohl(sid_tmp); /* uint32_t */
	memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
	i += sizeof(pid_t);
	pid_tmp = ntohl(pid_tmp); /* uint32_t */
	while (!(sid_tmp == 0 && pid_tmp == 0)) {
		if ((i + (2 * sizeof(pid_t))) > ECRYPTFS_SHM_SIZE) {
			syslog(LOG_ERR,
			       "No space left in shared memory region\n");
			rc = -ENOMEM;
			shmdt(shm_virt);
			goto out;
		}
		memcpy(&sid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		sid_tmp = ntohl(sid_tmp); /* uint32_t */
		memcpy(&pid_tmp, &shm_virt[i], sizeof(pid_t));
		i += sizeof(pid_t);
		pid_tmp = ntohl(pid_tmp); /* uint32_t */
	}
	pid = getpid();
	sid = getsid(pid);
	sid = htonl(sid);
	pid = htonl(pid);
	i -= (2 * sizeof(pid_t));
	memcpy(&shm_virt[i], &sid, sizeof(pid_t));
	i += sizeof(pid_t);
	memcpy(&shm_virt[i], &pid, sizeof(pid_t));
	i += sizeof(pid_t);
	if ((i + (2 * sizeof(pid_t))) <= ECRYPTFS_SHM_SIZE)
		memset(&shm_virt[i], 0, (i + (2 * sizeof(pid_t))));
	if ((rc = shmdt(shm_virt))) {
		syslog(LOG_ERR, "Error detaching from shared memory\n");
		rc = -EIO;
	}
out:
	return rc;
}

int ecryptfs_set_zombie_session_placeholder(void)
{
	int shm_id;
	int sem_id;
	int rc = 0;

	if ((rc = get_zombie_shared_mem_locked(&shm_id, &sem_id))) {
		syslog(LOG_ERR,
		       "Error getting shared memory segment\n");
		goto out;
	}
	if ((rc = add_sid_pid_pair_to_shm(shm_id))) {
		syslog(LOG_ERR, "Error adding sid/pid pair to shared memory "
		       "segment; rc = [%d]\n", rc);
		zombie_semaphore_unlock(sem_id);
		goto out;
	}
	zombie_semaphore_unlock(sem_id);
	sleep(ECRYPTFS_ZOMBIE_SLEEP_SECONDS);
	if ((rc = get_zombie_shared_mem_locked(&shm_id, &sem_id))) {
		syslog(LOG_ERR,
		       "Error getting shared memory segment\n");
		goto out;
	}
	if ((rc = remove_pid_for_this_sid(shm_id))) {
		syslog(LOG_ERR, "Error attempting to remove pid/sid "
		       "pair from shared memory segment; rc = [%d]\n",
		       rc);
		zombie_semaphore_unlock(sem_id);
		goto out;
	}
	zombie_semaphore_unlock(sem_id);
	exit(1);
out:
	return rc;
}

int ecryptfs_kill_and_clear_zombie_session_placeholder(void)
{
	int shm_id;
	int sem_id;
	int pid;
	int rc = 0;

	if ((rc = get_zombie_shared_mem_locked(&shm_id, &sem_id))) {
		syslog(LOG_ERR, "Error getting shared memory segment\n");
		goto out;
	}
	if ((rc = find_pid_for_this_sid(&pid, shm_id))) {
		syslog(LOG_ERR, "Error finding pid for sid in shared memory "
		       "segment; rc = [%d]\n", rc);
		zombie_semaphore_unlock(sem_id);
		goto out;
	}
	if (pid == 0) {
		syslog(LOG_WARNING, "No valid pid found for this sid\n");
	} else {
		if ((rc = kill(pid, SIGKILL))) {
			syslog(LOG_ERR, "Error attempting to kill process "
			       "[%d]; rc = [%d]; errno string = [%m]\n", pid,
			       rc);
		}
		if ((rc = remove_pid_for_this_sid(shm_id))) {
			syslog(LOG_ERR, "Error attempting to remove pid/sid "
			       "pair from shared memory segment; rc = [%d]\n",
			       rc);
			zombie_semaphore_unlock(sem_id);
			goto out;
		}
	}
	zombie_semaphore_unlock(sem_id);
out:
	return rc;
}

int ecryptfs_list_zombie_session_placeholders(void)
{
	int shm_id;
	int sem_id;
	int rc = 0;

	if ((rc = get_zombie_shared_mem_locked(&shm_id, &sem_id))) {
		syslog(LOG_ERR,
		       "Error getting shared memory segment\n");
		goto out;
	}
	if ((rc = list_pid_sid_pairs(shm_id))) {
		syslog(LOG_ERR, "Error listing sid/pid pairs in shared memory "
		       "segment; rc = [%d]\n", rc);
		zombie_semaphore_unlock(sem_id);
		goto out;
	}
	zombie_semaphore_unlock(sem_id);
out:
	return rc;
}

static struct ecryptfs_ctx_ops ctx_ops;

struct ecryptfs_ctx_ops *cryptfs_get_ctx_opts (void)
{
	return &ctx_ops;
}

