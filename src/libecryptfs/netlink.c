/**
 * Userspace side of netlink communications with eCryptfs kernel
 * module.
 *
 * Copyright (C) 2004-2007 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mhalcrow@us.ibm.com>
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

#include <errno.h>
#include <fcntl.h>
#include <signal.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#include <syslog.h>
#endif
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include "config.h"
#include "../include/ecryptfs.h"

int ecryptfs_send_netlink(struct ecryptfs_nl_ctx *nl_ctx,
			  struct ecryptfs_message *emsg, uint8_t msg_type,
			  uint16_t msg_flags, uint32_t msg_seq)
{
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl dst_addr;
	int payload_len;
	int rc;

	payload_len = emsg ? sizeof(*emsg) + emsg->data_len : 0;
	nlh = malloc(NLMSG_SPACE(payload_len));
	if (!nlh) {
		ecryptfs_syslog(LOG_ERR, "Failed to allocate memory for "
				"netlink header: %m\n");
		rc = -ENOMEM;
		goto out;
	}
	memset(&dst_addr, 0, sizeof(dst_addr));
	dst_addr.nl_family = AF_NETLINK;
	dst_addr.nl_pid = 0;
	dst_addr.nl_groups = 0;
	nlh->nlmsg_len = NLMSG_LENGTH(payload_len);
	nlh->nlmsg_seq = msg_seq;
	nlh->nlmsg_pid = 0;
	nlh->nlmsg_type = msg_type;
	nlh->nlmsg_flags = msg_flags;
	if (payload_len)
		memcpy(NLMSG_DATA(nlh), emsg, payload_len);
	rc = sendto(nl_ctx->socket_fd, nlh, nlh->nlmsg_len, 0,
		    (struct sockaddr *)&dst_addr, sizeof(dst_addr));
	if (rc < 0) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to send eCryptfs netlink "
		       "message: %m\n");
		goto out;
	}
out:
	free(nlh);
	return rc;
}

int ecryptfs_recv_netlink(struct ecryptfs_nl_ctx *nl_ctx,
			  struct ecryptfs_message **emsg,
			  int *msg_seq, uint8_t *msg_type)
{
	struct nlmsghdr *nlh = NULL;
	struct sockaddr_nl nladdr;
	socklen_t nladdr_len = sizeof(nladdr);
	int flags = MSG_PEEK;
	int buf_len = sizeof(*nlh);
	int pl_len;
	int rc;

receive:
	nlh = (struct nlmsghdr *)realloc(nlh, buf_len);
	if (!nlh) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to allocate memory for "
		       "netlink message: %m\n");
		goto out;
	}
	rc = recvfrom(nl_ctx->socket_fd, nlh, buf_len, flags,
		      (struct sockaddr*)&nladdr, &nladdr_len);
	if (rc < 0) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to receive netlink header; errno = "
		       "[%d]; errno msg = [%m]\n", errno);
		goto free_out;
	}
	if (flags & MSG_PEEK) {
		buf_len = nlh->nlmsg_len;
		flags &= ~MSG_PEEK;
		goto receive;
	}
	if (nladdr_len != sizeof(nladdr)) {
		rc = -EPROTO;
		syslog(LOG_ERR, "Received invalid netlink message\n");
		goto free_out;
	}
	if (nladdr.nl_pid) {
		rc = -ENOMSG;
		syslog(LOG_WARNING, "Received netlink packet from a "
				"userspace application; pid [%d] may be trying "
				"to spoof eCryptfs netlink packets\n",
				nladdr.nl_pid);
		goto out;
	}
	pl_len = NLMSG_PAYLOAD(nlh, 0);
	if (pl_len) {
		*emsg = malloc(pl_len);
		if (!*emsg) {
			rc = -errno;
			syslog(LOG_ERR, "Failed to allocate memory "
					"for eCryptfs netlink message: %m\n");
			goto free_out;
		}
		memcpy(*emsg, NLMSG_DATA(nlh), pl_len);
	}
	*msg_seq = nlh->nlmsg_seq;
	*msg_type = nlh->nlmsg_type;
free_out:
	free(nlh);
out:
	return rc;
}

int ecryptfs_init_netlink(struct ecryptfs_nl_ctx *nl_ctx)
{
	struct sockaddr_nl src_addr;
	int rc;

	nl_ctx->socket_fd = socket(PF_NETLINK, SOCK_RAW, NETLINK_ECRYPTFS);
	if (nl_ctx->socket_fd == -1) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to create the eCryptfs "
		       "netlink socket: [%m]\n");
		goto out;
	}
	memset(&src_addr, 0, sizeof(src_addr));
	src_addr.nl_family = AF_NETLINK;
	src_addr.nl_pid = getpid();
	src_addr.nl_groups = 0;
	rc = bind(nl_ctx->socket_fd, (struct sockaddr *)&src_addr,
		  sizeof(src_addr));
	if (rc) {
		rc = -errno;
		syslog(LOG_ERR, "Failed to bind the eCryptfs netlink "
		       "socket: %m\n");
		goto out;
	}
	syslog(LOG_DEBUG, "eCryptfs netlink socket was successfully "
	       "initialized\n");
out:
	return rc;
}

void ecryptfs_release_netlink(struct ecryptfs_nl_ctx *nl_ctx)
{
	if (nl_ctx->socket_fd)
		close(nl_ctx->socket_fd);
}

int ecryptfs_run_netlink_daemon(struct ecryptfs_nl_ctx *nl_ctx)
{
	struct ecryptfs_message *emsg = NULL;
	struct ecryptfs_ctx ctx;
	int msg_seq;
	uint8_t msg_type;
	int error_count = 0;
	int rc;

	memset(&ctx, 0, sizeof(struct ecryptfs_ctx));
	if ((rc = ecryptfs_register_key_modules(&ctx))) {
		syslog(LOG_ERR, "Failed to register key modules; rc = [%d]\n",
		       rc);
		goto out;
	}
receive:
	rc = ecryptfs_recv_netlink(nl_ctx, &emsg, &msg_seq, &msg_type);
	if (rc < 0) {
		syslog(LOG_ERR, "Error while receiving eCryptfs netlink "
		       "message; errno = [%d]; errno msg = [%m]\n", errno);
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
		rc = ecryptfs_send_netlink(nl_ctx, reply,
					   ECRYPTFS_MSG_RESPONSE, 0,
					   msg_seq);
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
