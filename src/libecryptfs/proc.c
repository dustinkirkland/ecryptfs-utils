/**
 * Userspace side of procfs communications with eCryptfs kernel
 * module.
 *
 * Copyright (C) 2008 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
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
#include <fcntl.h>
#include <signal.h>
#include <unistd.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#include <syslog.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"
#include "../include/ecryptfs.h"

int ecryptfs_send_proc(struct ecryptfs_proc_ctx *proc_ctx,
		       struct ecryptfs_message *msg, uint8_t msg_type,
		       uint16_t msg_flags, uint32_t msg_seq)
{
	uint32_t proc_msg_data_size;
	uint32_t packet_len_size;
	uint32_t packet_len;
	uint32_t msg_seq_be32;
	uint32_t i;
	ssize_t written;
	char packet_len_str[3];
	char *proc_msg_data;
	int rc;

	/* procfs packet format:
	 *  Octet 0: Type
	 *  Octets 1-4: network byte order msg_ctx->counter
	 *  Octets 5-N0: Size of struct ecryptfs_message to follow
	 *  Octets N0-N1: struct ecryptfs_message (including data) */
	packet_len = (sizeof(*msg) + msg->data_len);
	rc = ecryptfs_write_packet_length(packet_len_str, packet_len,
					  &packet_len_size);
	if (rc)
		goto out;
	proc_msg_data_size = (1 + 4 + packet_len_size + packet_len);
	proc_msg_data = malloc(proc_msg_data_size);
	if (!proc_msg_data) {
		rc = -ENOMEM;
		goto out;
	}
	msg_seq_be32 = htonl(msg_seq);
	i = 0;
	proc_msg_data[i++] = msg_type;
	memcpy(&proc_msg_data[i], (void *)&msg_seq_be32, 4);
	i += 4;
	memcpy(&proc_msg_data[i], packet_len_str, packet_len_size);
	i += packet_len_size;
	memcpy(&proc_msg_data[i], (void *)msg, packet_len);
	written = write(proc_ctx->proc_fd, proc_msg_data, proc_msg_data_size);
	if (written == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "Failed to send eCryptfs proc message; "
		       "errno msg = [%m]\n", errno);
	}
	free(proc_msg_data);
out:
	return rc;
}

/**
 * ecryptfs_recv_proc
 * @msg: Allocated in this function; callee must deallocate
 */
int ecryptfs_recv_proc(struct ecryptfs_proc_ctx *proc_ctx,
		       struct ecryptfs_message **msg, uint32_t *msg_seq,
		       uint8_t *msg_type)
{
	ssize_t read_bytes;
	uint32_t proc_msg_data_size;
	uint32_t packet_len_size;
	uint32_t packet_len;
	uint32_t msg_seq_be32;
	uint32_t i;
	char *proc_msg_data;
	int rc;

	proc_msg_data = malloc(ECRYPTFS_MSG_MAX_SIZE);
	if (!proc_msg_data) {
		rc = -ENOMEM;
		goto out;
	}
	read_bytes = read(proc_ctx->proc_fd, proc_msg_data,
			  ECRYPTFS_MSG_MAX_SIZE);
	if (read_bytes == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "%s: Error attempting to read message from "
		       "proc handle; errno msg = [%m]\n", __FUNCTION__, errno);
		goto out;
	}
	if (read_bytes < (1 + 4 + 1 + sizeof(**msg))) {
		rc = -EINVAL;
		syslog(LOG_ERR, "%s: Received invalid packet from kernel; "
		       "read_bytes = [%d]; minimum possible packet site is "
		       "[%d]\n", __FUNCTION__, read_bytes,
		       (1 + 4 + 1 + sizeof(**msg)));
		goto out;
	}
	i = 0;
	(*msg_type) = proc_msg_data[i++];
	memcpy((void *)&msg_seq_be32, &proc_msg_data[i], 4);
	i += 4;
	(*msg_seq) = ntohl(msg_seq_be32);
	rc = ecryptfs_parse_packet_length(&proc_msg_data[i], &packet_len,
					  &packet_len_size);
	if (rc)
		goto out;
	i += packet_len_size;
	proc_msg_data_size = (1 + 4 + packet_len_size + packet_len);
	if (proc_msg_data_size != read_bytes) {
		rc = -EINVAL;
		syslog(LOG_ERR, "%s: Invalid packet. (1 + 4 + "
		       "packet_len_size=[%d] + packet_len=[%d])=[%d] != "
		       "read_bytes=[%d]\n", __FUNCTION__, packet_len_size,
		       packet_len, (1 + 4 + packet_len_size + packet_len),
		       read_bytes);
		goto out;
	}
	(*msg) = malloc(packet_len);
	if (!(*msg)) {
		rc = -ENOMEM;
		goto out;
	}
	memcpy((void *)(*msg), (void *)&proc_msg_data[i], packet_len);
out:
	free(proc_msg_data);
	return rc;
}

int ecryptfs_init_proc(struct ecryptfs_proc_ctx *proc_ctx)
{
	char *ctl_fullpath;
	char *proc_mount_point;
	int ctl_fd;
	uid_t euid;
	int rc;

	rc = ecryptfs_get_proc_mount_point(&proc_mount_point);
	if (rc)
		goto out;
	rc = asprintf(&ctl_fullpath, "%s/fs/ecryptfs/ctl", proc_mount_point);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	ctl_fd = open(ctl_fullpath, O_RDONLY);
	if (ctl_fd == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "%s: Error whilst attempting to open [%s]; "
		       "errno msg = [%m]\n", __FUNCTION__, ctl_fullpath, errno);
		goto out_free;
	}
	rc = ioctl(ctl_fd, SIOCSIFMAP);
	close(ctl_fd);
	if (rc == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "%s: Error whilst attempting to ioctl [%s]; "
		       "errno msg = [%m]\n", __FUNCTION__, ctl_fullpath, errno);
		goto out_free;
	}
	euid = geteuid();
	rc = asprintf(&proc_ctx->proc_filename, "%s/fs/ecryptfs/%d",
		      proc_mount_point, euid);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
	proc_ctx->proc_fd = open(proc_ctx->proc_filename, O_RDWR);
	if (proc_ctx->proc_fd == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "%s: Error whilst attempting to open [%s]; "
		       "errno msg = [%m]\n", __FUNCTION__,
		       proc_ctx->proc_filename, errno);
	}
out_free:
	free(ctl_fullpath);
out:
	return rc;
}

void ecryptfs_release_proc(struct ecryptfs_proc_ctx *proc_ctx)
{
	char *ctl_fullpath;
	char *proc_mount_point;
	int ctl_fd;
	uid_t euid;
	int rc;

	close(proc_ctx->proc_fd);
	rc = ecryptfs_get_proc_mount_point(&proc_mount_point);
	if (rc)
		goto out;
	rc = asprintf(&ctl_fullpath, "%s/fs/ecryptfs/ctl", proc_mount_point);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	ctl_fd = open(ctl_fullpath, O_RDONLY);
	if (ctl_fd == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "%s: Error whilst attempting to open [%s]; "
		       "errno msg = [%m]\n", __FUNCTION__, ctl_fullpath, errno);
		goto out_free;
	}
	rc = ioctl(ctl_fd, SIOCSIFMAP);
	close(ctl_fd);
	if (rc == -1) {
		rc = -EIO;
		syslog(LOG_ERR, "%s: Error whilst attempting to ioctl [%s]; "
		       "errno msg = [%m]\n", __FUNCTION__, ctl_fullpath, errno);
		goto out_free;
	}
out_free:
	free(ctl_fullpath);
out:
	return;
}

int init_proc_daemon(void)
{
	return 0;
}

int ecryptfs_run_proc_daemon(struct ecryptfs_proc_ctx *proc_ctx)
{
	struct ecryptfs_message *emsg = NULL;
	struct ecryptfs_ctx ctx;
	int msg_seq;
	uint8_t msg_type;
	int error_count = 0;
	int rc;

	memset(&ctx, 0, sizeof(struct ecryptfs_ctx));
	rc = ecryptfs_register_key_modules(&ctx);
	if (rc) {
		syslog(LOG_ERR, "Failed to register key modules; rc = [%d]\n",
		       rc);
		goto out;
	}
receive:
	rc = ecryptfs_recv_proc(proc_ctx, &emsg, &msg_seq, &msg_type);
	if (rc < 0) {
		syslog(LOG_ERR, "Error while receiving eCryptfs netlink "
		       "message; errno = [%d]; errno msg = [%s]\n", errno,
		       strerror(errno));
		error_count++;
		if (error_count > ECRYPTFS_NETLINK_ERROR_COUNT_THRESHOLD) {
			syslog(LOG_ERR, "Netlink error threshold exceeded "
			       "maximum of [%d]; terminating daemon\n",
			       ECRYPTFS_NETLINK_ERROR_COUNT_THRESHOLD);
			rc = -EIO;
			goto out;
		}
	} else if (msg_type == ECRYPTFS_MSG_HELO) {
		syslog(LOG_DEBUG, "Received eCryptfs netlink HELO "
		       "message from the kernel\n");
		error_count = 0;
	} else if (msg_type == ECRYPTFS_MSG_QUIT) {
		syslog(LOG_DEBUG, "Received eCryptfs netlink QUIT "
		       "message from the kernel\n");
		free(emsg);
		rc = 0;
		goto out;
	} else if (msg_type == ECRYPTFS_MSG_REQUEST) {
		struct ecryptfs_message *reply = NULL;

		rc = parse_packet(&ctx, emsg, &reply);
		if (rc) {
			syslog(LOG_ERR, "Failed to process "
			       "netlink packet\n");
			free(reply);
			goto free_emsg;
		}
		reply->index = emsg->index;
		rc = ecryptfs_send_proc(proc_ctx, reply,
					ECRYPTFS_MSG_RESPONSE, 0, msg_seq);
		if (rc < 0) {
			syslog(LOG_ERR, "Failed to send netlink "
			       "message in response to kernel "
			       "request\n");
		}
		free(reply);
		error_count = 0;
	} else
		syslog(LOG_DEBUG, "Received unrecognized netlink "
		       "message type [%d]\n", msg_type);
free_emsg:
	free(emsg);
	goto receive;
out:
	ecryptfs_free_key_mod_list(&ctx);
	return rc;
}
