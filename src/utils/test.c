/**
 * Copyright (C) 2006 International Business Machines
 * Written by Michael A. Halcrow <mhalcrow@us.ibm.com>
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

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"
#include "ecryptfs.h"

#define ASSERT(EX)	                                                      \
do {	                                                                      \
        if (!(EX)) {                                                          \
	        printf("ASSERTION FAILED: %s at %s:%d (%s)\n", #EX,           \
	               __FILE__, __LINE__, __FUNCTION__);	              \
        }	                                                              \
} while (0)

struct ecryptfs_crypt_stat {
	int header_extent_size;
	int num_header_extents_at_front;
	int extent_size;
};

void
ecryptfs_extent_to_lwr_pg_idx_and_offset(unsigned long *lower_page_idx,
					 int *byte_offset,
					 struct ecryptfs_crypt_stat *crypt_stat,
					 unsigned long extent_num,
					 int page_size)
{
	unsigned long lower_extent_num;
	int extents_occupied_by_headers_at_front;
	int bytes_occupied_by_headers_at_front;
	int extent_offset;
	int extents_per_page;

	bytes_occupied_by_headers_at_front =
		( crypt_stat->header_extent_size
		  * crypt_stat->num_header_extents_at_front );
	extents_occupied_by_headers_at_front =
		( bytes_occupied_by_headers_at_front
		  / crypt_stat->extent_size );
	lower_extent_num = extents_occupied_by_headers_at_front + extent_num;
	extents_per_page = page_size / crypt_stat->extent_size;
	(*lower_page_idx) = lower_extent_num / extents_per_page;
	extent_offset = lower_extent_num % extents_per_page;
	(*byte_offset) = extent_offset * crypt_stat->extent_size;
}

struct translation_test_vector_element {
	int page_size;
	unsigned long header_extent_size;
	int num_header_extents_at_front;
	unsigned long extent_num;
	unsigned long lower_page_idx;
	int byte_offset;
};

#define ECRYPTFS_EXTENT_SIZE 4096 /* Test vector only valid for 4096 */

struct translation_test_vector_element translation_test_vector[] = {
	{4096,  8192, 1, 0, 2, 0},
	{4096,  8192, 1, 1, 3, 0},
	{4096,  8192, 1, 2, 4, 0},
	{4096,  8192, 1, 3, 5, 0},
	{8192,  8192, 1, 0, 1, 0},
	{8192,  8192, 1, 1, 1, 4096},
	{8192,  8192, 1, 2, 2, 0},
	{8192,  8192, 1, 3, 2, 4096},
	{8192,  8192, 1, 4, 3, 0},
	{16384, 8192, 1, 0, 0, 8192},
	{16384, 8192, 1, 1, 0, 12288},
	{16384, 8192, 1, 2, 1, 0},
	{16384, 8192, 1, 3, 1, 4096},
	{16384, 8192, 1, 4, 1, 8192},
	{16384, 8192, 1, 5, 1, 12288},
	{16384, 8192, 1, 6, 2, 0},
};

int test_extent_translation(void)
{
	struct ecryptfs_crypt_stat crypt_stat;
	unsigned long lower_page_idx;
	int byte_offset;
	int rc = 0;
	int i;

	printf("Testing ecryptfs_extent_to_lwr_pg_idx_and_offset()... ");
	crypt_stat.extent_size = ECRYPTFS_EXTENT_SIZE;
	for (i = 0;
	     i < (sizeof(translation_test_vector)
		  / sizeof(struct translation_test_vector_element));
	     i++) {
		crypt_stat.header_extent_size =
			translation_test_vector[i].header_extent_size;
		crypt_stat.num_header_extents_at_front =
		translation_test_vector[i].num_header_extents_at_front;
		ecryptfs_extent_to_lwr_pg_idx_and_offset(
			&lower_page_idx, &byte_offset, &crypt_stat,
			translation_test_vector[i].extent_num,
			translation_test_vector[i].page_size);
		if (lower_page_idx
		    != translation_test_vector[i].lower_page_idx) {
			rc = -1;
			printf("\nError on test vector entry [%d]; "
			       "lower_page_idx = [%lu]\n", i, lower_page_idx);
			goto out;
		}
		if (byte_offset
		    != translation_test_vector[i].byte_offset) {
			rc = -1;
			printf("\nError on test vector entry [%d]; "
			       "byte offset = [%d]\n", i, byte_offset);
			goto out;
		}
	}
out:
	if (!rc) {
		printf("Pass\n");
	}
	return rc;
}

struct page {
	unsigned long index;
};

struct inode {
};

struct file {
};

struct writeback_control {
};

struct ecryptfs_page_crypt_context {
	struct page *page;
#define ECRYPTFS_PREPARE_COMMIT_MODE 0
#define ECRYPTFS_WRITEPAGE_MODE      1
	int mode;
	union {
		struct file *lower_file;
		struct writeback_control *wbc;
	} param;
};

void ecryptfs_unmap_and_release_lower_page(struct page *lower_page)
{
	printf("%s: Called w/ lower_page = [%p]\n", __FUNCTION__, lower_page);
	free(lower_page);
}

int
ecryptfs_commit_lower_page(struct page *lower_page, struct inode *lower_inode,
			   struct file *lower_file, int byte_offset,
			   int region_size)
{
	int rc = 0;

	printf("%s: Called w/ lower_page = [%p], lower_inode = [%p], "
	       "lower_file = [%p], byte_offset = [%d], region_size = [%d]\n",
	       __FUNCTION__,
	       lower_page, lower_inode, lower_file, byte_offset, region_size);
	ecryptfs_unmap_and_release_lower_page(lower_page);
	return rc;
}

int ecryptfs_writepage_and_release_lower_page(struct page *lower_page,
					      struct inode *lower_inode,
					      struct writeback_control *wbc)
{
	printf("%s: Called w/ lower_page = [%p], lower_inode = [%p], wbc = "
	       "[%p]\n", __FUNCTION__, lower_page, lower_inode, wbc);
	return 0;
}

int ecryptfs_write_out_page(struct ecryptfs_page_crypt_context *ctx,
			    struct page *lower_page, struct inode *lower_inode,
			    int byte_offset_in_page, int bytes_to_write)
{
	int rc = 0;

	rc = ecryptfs_commit_lower_page(lower_page, lower_inode,
					NULL,
					byte_offset_in_page,
					bytes_to_write);
	return rc;
}

int ecryptfs_get_lower_page(struct page **lower_page, struct inode *lower_inode,
			    struct file *lower_file,
			    unsigned long lower_page_index, int byte_offset,
			    int region_bytes)
{
	printf("%s: Called w/ **lower_page = [%p], lower_inode = [%p], "
	       "lower_file = [%p], lower_page_index = [%lu], byte_offset = "
	       "[%d], region_bytes = [%d]\n", __FUNCTION__, lower_page,
	       lower_inode, lower_file, lower_page_index, byte_offset,
	       region_bytes);
	printf("[Call to prepare_write]\n");
	(*lower_page) = (struct page *)malloc(sizeof(struct page));
	(*lower_page)->index = lower_page_index;
	return 0;
}

int ecryptfs_read_in_page(struct ecryptfs_page_crypt_context *ctx,
			  struct page **lower_page, struct inode *lower_inode,
			  unsigned long lower_page_idx, int byte_offset_in_page,
			  int page_cache_size)
{
	int rc = 0;

	printf("%s: Called w/ **lower_page = [%p], lower_inode = [%p]; "
	       "lower_page_idx "
	       "= [%lu], byte_offset_in_page = [%d]\n", __FUNCTION__,
	       lower_page, lower_inode,
	       lower_page_idx, byte_offset_in_page);
	rc = ecryptfs_get_lower_page(lower_page, lower_inode,
				     NULL,
				     lower_page_idx,
				     byte_offset_in_page,
				     (page_cache_size
				      - byte_offset_in_page));
	return rc;
}

int ecryptfs_derive_iv(char *iv, struct ecryptfs_crypt_stat *crypt_stat,
		       unsigned long offset)
{
	printf("%s: Called w/ offset = [%lu]\n", __FUNCTION__, offset);
	return 0;
}

int
ecryptfs_encrypt_page_offset(struct ecryptfs_crypt_stat *crypt_stat,
			     struct page *dst_page, int dst_offset,
			     struct page *src_page, int src_offset, int size,
			     unsigned char *iv)
{
	printf("%s: Called:\n * dst_page->index = [%lu]\n * dst_offset = [%d]\n"
	       " * src_page->index = [%lu]\n * src_offset = [%d]\n",
	       __FUNCTION__, dst_page->index, dst_offset, src_page->index,
	       src_offset);
	return 0;
}

#define ECRYPTFS_MAX_IV_BYTES 16

int ecryptfs_encrypt_page(int page_cache_size, int extent_size,
			  struct page *page, int header_extent_size,
			  int num_header_extents_at_front)
{
	char extent_iv[ECRYPTFS_MAX_IV_BYTES];
	unsigned long base_extent;
	unsigned long extent_offset = 0;
	unsigned long lower_page_idx = 0;
	unsigned long prior_lower_page_idx = 0;
	struct page *lower_page;
	struct inode *lower_inode;
	struct ecryptfs_crypt_stat *crypt_stat;
	int rc = 0;
	int lower_byte_offset;
	int orig_byte_offset = 0;
	int num_extents_per_page;
#define ECRYPTFS_PAGE_STATE_UNREAD    0
#define ECRYPTFS_PAGE_STATE_READ      1
#define ECRYPTFS_PAGE_STATE_MODIFIED  2
#define ECRYPTFS_PAGE_STATE_WRITTEN   3
	int page_state;

	crypt_stat = (struct ecryptfs_crypt_stat *)malloc(
		sizeof(struct ecryptfs_crypt_stat));
	if (!crypt_stat) {
		rc = 1;
		goto out;
	}
	crypt_stat->extent_size = extent_size;
	crypt_stat->header_extent_size = header_extent_size;
	crypt_stat->num_header_extents_at_front = num_header_extents_at_front;

	lower_inode = NULL;
	num_extents_per_page = page_cache_size / crypt_stat->extent_size;
	base_extent = (page->index * num_extents_per_page);
	page_state = ECRYPTFS_PAGE_STATE_UNREAD;
	while (extent_offset < num_extents_per_page) {
		ecryptfs_extent_to_lwr_pg_idx_and_offset(
			&lower_page_idx, &lower_byte_offset, crypt_stat,
			(base_extent + extent_offset), page_cache_size);
		if (prior_lower_page_idx != lower_page_idx
		    && page_state == ECRYPTFS_PAGE_STATE_MODIFIED) {
			rc = ecryptfs_write_out_page(NULL, lower_page,
						     lower_inode,
						     orig_byte_offset,
						     (page_cache_size
						      - orig_byte_offset));
			page_state = ECRYPTFS_PAGE_STATE_WRITTEN;
		}
		if (page_state == ECRYPTFS_PAGE_STATE_UNREAD
		    || page_state == ECRYPTFS_PAGE_STATE_WRITTEN) {
			rc = ecryptfs_read_in_page(NULL, &lower_page,
						   lower_inode, lower_page_idx,
						   lower_byte_offset,
						   page_cache_size);
			orig_byte_offset = lower_byte_offset;
			prior_lower_page_idx = lower_page_idx;
			page_state = ECRYPTFS_PAGE_STATE_READ;
		}
		ASSERT(page_state == ECRYPTFS_PAGE_STATE_MODIFIED
		       || page_state == ECRYPTFS_PAGE_STATE_READ);
		rc = ecryptfs_derive_iv(extent_iv, crypt_stat,
					(base_extent + extent_offset));
		rc = ecryptfs_encrypt_page_offset(
			crypt_stat, lower_page, lower_byte_offset, page,
			(extent_offset * crypt_stat->extent_size),
			crypt_stat->extent_size, (unsigned char *)extent_iv);
		page_state = ECRYPTFS_PAGE_STATE_MODIFIED;
		extent_offset++;
	}
	ASSERT(orig_byte_offset == 0);
	rc = ecryptfs_write_out_page(NULL, lower_page, lower_inode, 0,
				     (lower_byte_offset
				      + crypt_stat->extent_size));
out:
	if (crypt_stat)
		free(crypt_stat);
	return rc;
}

int test_encrypt(void)
{
	int rc = 0;
	struct page page;

	page.index = 0;
	/* int ecryptfs_encrypt_page(int page_cache_size, int extent_size,
	   struct page *page, int header_extent_size,
	   int num_header_extents_at_front) */
	rc = ecryptfs_encrypt_page(16384, /* page_cache_size */
				   4096, /* extent_size */
				   &page,
				   8192, /* header size */
				   1); /* num_headers */
	return rc;
}

unsigned long
upper_size_to_lower_size(struct ecryptfs_crypt_stat *crypt_stat,
			 unsigned long upper_size)
{
	unsigned long lower_size;

	lower_size = ( crypt_stat->header_extent_size
		       * crypt_stat->num_header_extents_at_front );
	if (upper_size != 0) {
		unsigned long num_extents;

		num_extents = upper_size / crypt_stat->extent_size;
		if (upper_size % crypt_stat->extent_size)
			num_extents++;
		lower_size += (num_extents * crypt_stat->extent_size);
	}
	return lower_size;
}

struct upper_lower_test_vector_element {
	unsigned long header_extent_size;
	int num_header_extents_at_front;
	int extent_size;
	unsigned long upper_size;
	unsigned long lower_size;
};

struct upper_lower_test_vector_element upper_lower_test_vector[] = {
	{8192, 1, 4096, 0, 8192},
	{8192, 1, 4096, 1, 12288},
	{8192, 1, 4096, 2, 12288},
	{8192, 1, 4096, 4094, 12288},
	{8192, 1, 4096, 4095, 12288},
	{8192, 1, 4096, 4096, 12288},
	{8192, 1, 4096, 4097, 16384},
	{8192, 1, 4096, 4098, 16384},
	{8192, 1, 4096, 8191, 16384},
	{8192, 1, 4096, 8192, 16384},
	{8192, 1, 4096, 8193, 20480}
};

int test_upper_size_to_lower_size(void)
{
	int rc = 0;
	unsigned long lower_size;
	struct ecryptfs_crypt_stat crypt_stat;
	int i;

	for (i = 0;
	     i < (sizeof(upper_lower_test_vector)
		  / sizeof(struct upper_lower_test_vector_element));
	     i++) {
		crypt_stat.header_extent_size =
			upper_lower_test_vector[i].header_extent_size;
		crypt_stat.num_header_extents_at_front =
			upper_lower_test_vector[i].num_header_extents_at_front;
		crypt_stat.extent_size = upper_lower_test_vector[i].extent_size;
		lower_size = upper_size_to_lower_size(
			&crypt_stat, upper_lower_test_vector[i].upper_size);
		if (lower_size != upper_lower_test_vector[i].lower_size) {
			printf("Unexpected lower size [%lu] for upper size "
			       "[%lu]\n", lower_size,
			       upper_lower_test_vector[i].upper_size);
			rc = -1;
			goto out;
		}
	}
out:
	return rc;
}

int test_nv_list_from_file(void)
{
	int rc = 0;
	struct ecryptfs_name_val_pair nv_pair_head;
	struct ecryptfs_name_val_pair *cursor;
	int fd;

	nv_pair_head.next = NULL;
	fd = open("ecryptfsrc", O_RDONLY);
	if (fd == -1) {
		rc = -EIO;
		goto out;
	}
	rc = parse_options_file(fd, &nv_pair_head);
	close(fd);
	cursor = nv_pair_head.next;
	while (cursor) {
		printf("cursor->name = [%s]\n", cursor->name);
		printf("cursor->value = [%s]\n\n", cursor->value);
		cursor = cursor->next;
	}
out:
	return rc;
}

int main()
{
	int rc = 0;

	rc = test_nv_list_from_file();
	goto out;
	rc = test_extent_translation();
	if (rc)
		goto out;
	rc = test_encrypt();
	if (rc)
		goto out;
	rc = test_upper_size_to_lower_size();
	if (rc)
		goto out;
out:
	return rc;
}
