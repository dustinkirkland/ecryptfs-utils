/**
 * Copyright (C) 2006 International Business Machines Corp.
 *   Author(s): Michael A. Halcrow <mahalcro@us.ibm.com>
 *              Trevor Highland <trevor.highland@gmail.com>
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
#ifndef S_SPLINT_S
#include <sys/ioctl.h>
#include <sys/types.h>
#include <sys/stat.h>
#endif /* S_SPLINT_S */
#include <sys/mman.h>
#include <fcntl.h>
#include <string.h>
#ifndef S_SPLINT_S
#include <stdio.h>
#include <syslog.h>
#endif /* S_SPLINT_S */
#include <errno.h>
#include <stdlib.h>
#include <pwd.h>
#include "../include/ecryptfs.h"

#define MAX_TOK_LEN 128
#define MAX_FILE_SIZE 0xa000

int print_nvp_list(struct ecryptfs_name_val_pair *dst)
{
	syslog(LOG_ERR, "Printing nvp list\n");
	while (dst) {
		syslog(LOG_ERR, "name=%s\n", dst->name);
		syslog(LOG_ERR, "val=%s\n", dst->value);
		dst = dst->next;
	}
	return 0;
}

static int copy_nv_pair(struct ecryptfs_name_val_pair *dst,
			 struct ecryptfs_name_val_pair *src)
{
	int rc;

	dst->flags = src->flags;
	if ((rc = asprintf(&dst->name, "%s", src->name)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	if ((rc = asprintf(&dst->value, "%s", src->value)) == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = 0;
out:
	return rc;
}

/**
 * For each name in dst that is also in src, set the value in dst to
 * that which is in src.
 *
 * For each name in src that is not in dst, append a copy of the node
 * onto dst.
 *
 * TODO: This function sucks. Partially because the nv data structure
 * sucks. Overhaul it sometime.
 */
int ecryptfs_nvp_list_union(struct ecryptfs_name_val_pair *dst,
			    struct ecryptfs_name_val_pair *src,
			    struct ecryptfs_name_val_pair *allowed_duplicates)
{
	int rc = 0;
	struct ecryptfs_name_val_pair *dst_cursor;
	struct ecryptfs_name_val_pair *src_cursor;

	src_cursor = src->next;
	while (src_cursor) {
		int found_match;
		struct ecryptfs_name_val_pair *prev_dst_cursor;
		struct ecryptfs_name_val_pair *ad_cursor;

		if (!src_cursor->name)
			goto next_src_cursor;
		found_match = 0;
		prev_dst_cursor = dst;
		dst_cursor = dst->next;
		ad_cursor = allowed_duplicates->next;
		while (ad_cursor) {
			if (strcmp(src_cursor->name, ad_cursor->name) == 0) {
				if (ecryptfs_verbosity)
					syslog(LOG_INFO,
					       "Duplicates allowed for [%s]\n",
						src_cursor->name);
				while (dst_cursor) {
					prev_dst_cursor = dst_cursor;
					dst_cursor = dst_cursor->next;
				}
				goto do_insert;
			}
			ad_cursor = ad_cursor->next;
		}
		while (dst_cursor) {
			if (!dst_cursor->name)
				goto next_dst_cursor;
			if (strcmp(src_cursor->name, dst_cursor->name) == 0) {
				found_match = 1;
				free(dst_cursor->value);
				rc = asprintf(&dst_cursor->value, "%s",
					      src_cursor->value);
				if (rc == -1) {
					rc = -ENOMEM;
					goto out;
				}
				rc = 0;
			}
next_dst_cursor:
			prev_dst_cursor = dst_cursor;
			dst_cursor = dst_cursor->next;
		}
do_insert:
		if (!found_match) {
			struct ecryptfs_name_val_pair *dst_tmp;
			struct ecryptfs_name_val_pair *src_tmp;
			int i;

			prev_dst_cursor->next = dst_cursor =
				malloc(sizeof(struct ecryptfs_name_val_pair));
			memset(dst_cursor, 0,
			       sizeof(struct ecryptfs_name_val_pair));
			if (!dst_cursor) {
				rc = -ENOMEM;
				goto out;
			}
			dst_cursor->next = NULL;
			if ((rc = copy_nv_pair(dst_cursor, src_cursor))) {
				goto out;
			}
			dst_tmp = dst_cursor;
			src_tmp = src_cursor;
			/* TODO: Okay; this has officially become a
			 * hack. It's time to switch to a real tree
			 * structure for the name/value pair list. */
			for (i = 0; i < NV_MAX_CHILDREN; i++) {
				if (src_cursor->children[i]) {
					if ((dst_cursor->children[i]
					     = malloc(sizeof(struct ecryptfs_name_val_pair)))
					    == NULL) {
						rc = -ENOMEM;
						goto out;
					}
					memset(dst_cursor->children[i], 0,
					       sizeof(struct ecryptfs_name_val_pair));
					copy_nv_pair(dst_cursor->children[i],
						     src_cursor->children[i]);
					dst_tmp->next = dst_cursor->children[i];
					prev_dst_cursor = dst_tmp;
					dst_tmp = dst_tmp->next;
					prev_dst_cursor->next = dst_tmp;
					src_tmp = src_tmp->next;
					if (src_tmp != src_cursor->children[i]) {
						rc = -EINVAL;
						syslog(LOG_ERR,
						       "Internal error: src_tmp"
						       "->next != src_cursor->c"
						       "hildren[%d]\n", i);
						goto out;
					}
				}
			}
			dst_cursor = dst_tmp;
			src_cursor = src_tmp;
		}
next_src_cursor:
		src_cursor = src_cursor->next;
	}
out:
	return rc;
}

int
ecryptfs_parse_rc_file_fullpath(struct ecryptfs_name_val_pair *nvp_list_head,
				char *fullpath)
{
	int rc;
	int fd;

	fd = open(fullpath, O_RDONLY);
	if (fd == -1) {
		rc = -errno;
		goto out;
	}
	rc = parse_options_file(fd, nvp_list_head);
	close(fd);
out:
	return rc;
}

int ecryptfs_parse_rc_file(struct ecryptfs_name_val_pair *nvp_list_head)
{
	char *home;
	uid_t uid;
	struct passwd *pw;
	char *rcfile_fullpath;
	int rc;

	uid = getuid();
	pw = getpwuid(uid);
	if (!pw) {
		rc = -EIO;
		goto out;
	}
	home = pw->pw_dir;
	rc = asprintf(&rcfile_fullpath, "%s/.ecryptfsrc", home);
	if (rc == -1) {
		rc = -ENOMEM;
		goto out;
	}
	rc = ecryptfs_parse_rc_file_fullpath(nvp_list_head, rcfile_fullpath);
	free(rcfile_fullpath);
out:
	return rc;
}

int process_comma_tok(struct ecryptfs_name_val_pair **current, char *tok,
		      /*@null@*/ char *prefix)
{
	int tok_len = (int)strlen(tok);
	char new_prefix[MAX_TOK_LEN];
	char sub_token[MAX_TOK_LEN];
	char *name = NULL;
	char *value = NULL;
	int i, j, st_len;
	int rc = 0;

	if(tok && tok[0] == '\0') {
		goto out;
	}
	if (tok_len < 0 || tok_len > MAX_TOK_LEN) {
		rc = -EINVAL;
		goto out;
	}
	if (tok[0] == '=' || tok[0] == ':') {
		rc = -EINVAL;
		goto out;
	}
	j = 0;
	if (tok_len > 4 && !memcmp(tok, "key=", 4))
		for (i = 4; i < tok_len; i++) {
			if (tok[i] == ':')
				goto process_colon_list;
		}
	goto process_nv_pair;
process_colon_list:
	new_prefix[j] = '\0';
	i = 0;
	j = 0;
	while (i < tok_len) {
		if (tok[i] == ':') {
			sub_token[j] = '\0';
			if ((rc = process_comma_tok(current, sub_token, NULL)))
				goto out;
			j = 0;
		} else
			sub_token[j++] = tok[i];
		i++;
	}
	sub_token[j] = '\0';
	rc = process_comma_tok(current, sub_token, new_prefix);
	goto out;
process_nv_pair:
	st_len = snprintf(sub_token, MAX_TOK_LEN, "%s%s",
			  (prefix ? prefix : ""), tok);
	j = 0;
	for (i = 0; i < st_len; i++)
		if (sub_token[i] == '=') {
			if (!(name = malloc(i + 1))) {
				rc = -ENOMEM;
				goto out;
			}
			memcpy(name, sub_token, i);
			name[i] = '\0';
			j = i;
		}
	if (!name) {
		if (!(name = malloc(i+1))) {
			rc = -ENOMEM;
			goto out;
		}
		memcpy(name, sub_token, i);
		name[i] = '\0';
	} else {
		if((i-j) > 1) {
			if (!(value = malloc(i - j + 1))) {
				rc = -ENOMEM;
				goto out;
			}
			memcpy(value, &sub_token[j+1], (i - j));
			value[(i - j)] = '\0';
		}
	}
	if (!((*current)->next =
	      malloc(sizeof(struct ecryptfs_name_val_pair)))) {
		rc = -ENOMEM;
		goto out;
	}
	memset((*current)->next, 0, sizeof(struct ecryptfs_name_val_pair));
	if (strlen(name) == 0) {
		free(name);
		free(value);
	} else {
		*current = (*current)->next;
		(*current)->name = name;
		(*current)->value = value;
		(*current)->next = NULL;
	}
out:
	return rc;
}

/**
 * name=val,key=PKI:name1=val1:name2=val2,name=val...
 */
int generate_nv_list(struct ecryptfs_name_val_pair *head, char *buf)
{
	struct ecryptfs_name_val_pair *current = head;
	char tok_str[MAX_TOK_LEN];

	if (!buf)
		return 0;

	int buf_len = strlen(buf);
	int i, j = 0;
	int rc = 0;

	for (i = 0; i < buf_len; i++) {
		if (buf[i] == ',' || buf[i] == '\n') {
			tok_str[j] = '\0';
			if ((rc = process_comma_tok(&current, tok_str, NULL)))
				goto out;
			j = 0;
		} else
			tok_str[j++] = buf[i];
		if (j == MAX_TOK_LEN)
			goto out;
	}
	tok_str[j] = '\0';
	if ((rc = process_comma_tok(&current, tok_str, NULL)))
		goto out;
out:
	return rc;
}

int ecryptfs_parse_options(char *opts, struct ecryptfs_name_val_pair *head)
{
	return generate_nv_list(head, opts);
}

int parse_options_file(int fd, struct ecryptfs_name_val_pair *head)
{
	int rc = 0;
	char *data;
	off_t buf_size, pos;
	struct stat filestat;

	rc = fstat(fd, &filestat);
	if (rc) {
		syslog(LOG_ERR, "%s: fstat returned [%d] on fd [%d]\n",
		       __FUNCTION__, rc, fd);
		goto out;
	}
	if (S_ISDIR(filestat.st_mode)) {
		rc = -EISDIR;
		goto out;
	}
	if (S_ISFIFO(filestat.st_mode)) {
		buf_size = 1024;
	} else {
		buf_size = filestat.st_size;
	}
	if (buf_size > MAX_FILE_SIZE) {
		syslog(LOG_ERR, "File size too large\n");
		rc = -EFBIG;
		goto out;
	}
	buf_size += 1;
	data = (char *)malloc(buf_size);
	if (!data) {
		rc = -ENOMEM;
		goto out;
	}
	pos = 0;
	while (1) {
		rc = read(fd, data + pos, buf_size - pos);
		if (rc == 0)
			break;
		if (rc == -1) {
			rc = -errno;
			syslog(LOG_ERR, "%s: read failed on fd [%d]; rc = [%d]\n",
		       		__FUNCTION__, fd, rc);
			goto out_free;
		}
		pos += rc;
		if (pos >= buf_size) {
			char *more_data;

			buf_size *= 2;
			more_data = (char *)realloc(data, buf_size);
			if (!more_data) {
				rc = -ENOMEM;
				goto out_free;
			}
			data = more_data;
		}
	}
	rc = generate_nv_list(head, data);
out_free:
	free(data);
out:
	return rc;
}
