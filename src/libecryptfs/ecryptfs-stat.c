#include <unistd.h>
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
	int i;
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

int ecryptfs_parse_stat(struct ecryptfs_crypt_stat_user *crypt_stat, char *buf,
			size_t buf_size)
{
	int big_endian;
	uint64_t file_size;
	int rc = 0;

	if (buf_size < ECRYPTFS_FILE_SIZE_BYTES) {
		printf("Invalid metadata size; must have at least [%d] bytes; "
		       "there are only [%d] bytes\n", ECRYPTFS_FILE_SIZE_BYTES,
		       buf_size);
		rc = -EINVAL;
		goto out;
	}
	memset(crypt_stat, 0, sizeof(*crypt_stat));
	memcpy(&file_size, buf, ECRYPTFS_FILE_SIZE_BYTES);
	big_endian = host_is_big_endian();
	if (!big_endian)
		file_size = swab64(file_size);
	crypt_stat->file_size = file_size;
out:
	return rc;
}
