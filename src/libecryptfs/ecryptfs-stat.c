#include <unistd.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include "../include/ecryptfs.h"

static uint64_t swab64(uint64_t x)
{
	return x<<56 | x>>56 |
		(x & (uint64_t)0x000000000000ff00ULL)<<40 |
		(x & (uint64_t)0x0000000000ff0000ULL)<<24 |
		(x & (uint64_t)0x00000000ff000000ULL)<< 8 |
	        (x & (uint64_t)0x000000ff00000000ULL)>> 8 |
		(x & (uint64_t)0x0000ff0000000000ULL)>>24 |
		(x & (uint64_t)0x00ff000000000000ULL)>>40;
}

static int host_is_big_endian(void)
{
	uint32_t tmp_u32;
	char tmp_str[sizeof(uint32_t)];

	tmp_u32 = 0x00000001;
	memcpy(tmp_str, (char *)&tmp_u32, sizeof(uint32_t));
	if (tmp_str[0] == 0x01)
		return 0; /* If the first byte contains 0x01, host is
			     little endian (e.g., x86). Reverse what's
			     read from disk. */
	else
		return 1; /* If the first byte contains 0x00, host is
			   * big endian (e.g., ppc). Just copy from
			   * disk. */
}

/**
 * contains_ecryptfs_marker - check for the ecryptfs marker
 * @data: The data block in which to check
 *
 * Returns one if marker found; zero if not found
 */
static int ecryptfs_contains_ecryptfs_marker(char *data)
{
	uint32_t m_1, m_2;
	int big_endian;

	big_endian = host_is_big_endian();
	memcpy(&m_1, data, 4);
	if (!big_endian)
		m_1 = ntohl(m_1);
	memcpy(&m_2, (data + 4), 4);
	if (!big_endian)
		m_2 = ntohl(m_2);
	if ((m_1 ^ MAGIC_ECRYPTFS_MARKER) == m_2)
		return 1;
	return 0;
}

struct ecryptfs_flag_map_elem {
	uint32_t file_flag;
	uint32_t local_flag;
};

/* Add support for additional flags by adding elements here. */
static struct ecryptfs_flag_map_elem ecryptfs_flag_map[] = {
	{0x00000001, ECRYPTFS_ENABLE_HMAC},
	{0x00000002, ECRYPTFS_ENCRYPTED},
	{0x00000004, ECRYPTFS_METADATA_IN_XATTR}
};

/**
 * ecryptfs_process_flags
 * @crypt_stat: The cryptographic context
 * @page_virt: Source data to be parsed
 * @bytes_read: Updated with the number of bytes read
 *
 * Returns zero on success; non-zero if the flag set is invalid
 */
static int ecryptfs_process_flags(struct ecryptfs_crypt_stat_user *crypt_stat,
				  char *buf, int *bytes_read)
{
	int rc = 0;
	int i;
	uint32_t flags;
	int big_endian;

	big_endian = host_is_big_endian();
	memcpy(&flags, buf, 4);
	if (!big_endian)
		flags = ntohl(flags);
	for (i = 0; i < ((sizeof(ecryptfs_flag_map)
			  / sizeof(struct ecryptfs_flag_map_elem))); i++)
		if (flags & ecryptfs_flag_map[i].file_flag) {
			crypt_stat->flags |= ecryptfs_flag_map[i].local_flag;
		} else
			crypt_stat->flags &= ~(ecryptfs_flag_map[i].local_flag);
	/* Version is in top 8 bits of the 32-bit flag vector */
	crypt_stat->file_version = ((flags >> 24) & 0xFF);
	(*bytes_read) = 4;
	return rc;
}

#define ECRYPTFS_DONT_VALIDATE_HEADER_SIZE 0
#define ECRYPTFS_VALIDATE_HEADER_SIZE 1
static int
ecryptfs_parse_header_metadata(struct ecryptfs_crypt_stat_user *crypt_stat,
			       char *buf, int *bytes_read,
			       int validate_header_size)
{
	int rc = 0;
	uint32_t header_extent_size;
	uint16_t num_header_extents_at_front;
	int big_endian;

	big_endian = host_is_big_endian();
	memcpy(&header_extent_size, buf, sizeof(uint32_t));
	if (!big_endian)
		header_extent_size = ntohl(header_extent_size);
	buf += sizeof(uint32_t);
	memcpy(&num_header_extents_at_front, buf, sizeof(uint16_t));
	if (!big_endian)
		num_header_extents_at_front =
			ntohs(num_header_extents_at_front);
	crypt_stat->num_header_bytes_at_front =
		(((size_t)num_header_extents_at_front
		  * (size_t)header_extent_size));
	(*bytes_read) = (sizeof(uint32_t) + sizeof(uint16_t));
	if ((validate_header_size == ECRYPTFS_VALIDATE_HEADER_SIZE)
	    && (crypt_stat->num_header_bytes_at_front
		< ECRYPTFS_MINIMUM_HEADER_EXTENT_SIZE)) {
		rc = -EINVAL;
		printf("%s Invalid header size: [%zu]\n", __FUNCTION__,
		       crypt_stat->num_header_bytes_at_front);
	}
	return rc;
}

int ecryptfs_parse_stat(struct ecryptfs_crypt_stat_user *crypt_stat, char *buf,
			size_t buf_size)
{
	uint64_t file_size;
	int bytes_read;
	int big_endian;
	int rc = 0;

	if (buf_size < (ECRYPTFS_FILE_SIZE_BYTES
			+ MAGIC_ECRYPTFS_MARKER_SIZE_BYTES
			+ 4)) {
		printf("%s: Invalid metadata size; must have at least [%zu] "
		       "bytes; there are only [%zu] bytes\n", __FUNCTION__,
		       (ECRYPTFS_FILE_SIZE_BYTES
			+ MAGIC_ECRYPTFS_MARKER_SIZE_BYTES
			+ 4), buf_size);
		rc = -EINVAL;
		goto out;
	}
	memset(crypt_stat, 0, sizeof(*crypt_stat));
	memcpy(&file_size, buf, ECRYPTFS_FILE_SIZE_BYTES);
	buf += ECRYPTFS_FILE_SIZE_BYTES;
	big_endian = host_is_big_endian();
	if (!big_endian)
		file_size = swab64(file_size);
	crypt_stat->file_size = file_size;
	rc = ecryptfs_contains_ecryptfs_marker(buf);
	if (rc != 1) {
		printf("%s: Magic eCryptfs marker not found in header.\n",
		       __FUNCTION__);
		rc = -EINVAL;
		goto out;
	}
	buf += MAGIC_ECRYPTFS_MARKER_SIZE_BYTES;
	rc = ecryptfs_process_flags(crypt_stat, buf, &bytes_read);
	if (rc) {
		printf("%s: Invalid header content.\n", __FUNCTION__);
		goto out;
	}
	buf += bytes_read;
	rc = ecryptfs_parse_header_metadata(crypt_stat, buf, &bytes_read,
					    ECRYPTFS_VALIDATE_HEADER_SIZE);
	if (rc) {
		printf("%s: Invalid header content.\n", __FUNCTION__);
		goto out;
	}
	buf += bytes_read;
/*	rc = ecryptfs_parse_packet_set(crypt_stat, buf); */
out:
	return rc;
}
