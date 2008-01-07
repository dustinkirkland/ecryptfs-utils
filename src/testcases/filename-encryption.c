#include <stdio.h>
#include <string.h>

#define u8 unsigned char

/**
 * Temporary holding place for functions relating to filename
 * encryption
 */

/* 64 characters forming a 6-bit target field */
static char *portable_filename_chars = ("-.0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
					"abcdefghijklmnopqrstuvwxyz");

static char filename_rev_map[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
	0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 63 */
	0x00, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, /* 71 */
	0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, /* 79 */
	0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, /* 87 */
	0x23, 0x24, 0x25, 0x00, 0x00, 0x00, 0x00, 0x00, /* 95 */
	0x00, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, /* 103 */
	0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, /* 111 */
	0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, /* 119 */
	0x3D, 0x3E, 0x3F
};

/**
 * ecryptfs_encode_for_filename
 * @src_size Size of the source in bytes
 * 
 */
int ecryptfs_encode_for_filename(char *dst, size_t *dst_size, char *src,
				 size_t src_size)
{
	size_t src_bit_offset = 0;
	size_t src_byte_offset = 0;
	size_t dst_byte_offset = 0;
	u8 current_bit_offset = 0;
	int rc = 0;

	while (src_bit_offset < ((src_size) * 8)) {
		src_byte_offset = (src_bit_offset / 8);
		switch (current_bit_offset) {
		case 0:
			dst[dst_byte_offset++] =
				portable_filename_chars[
					(src[src_byte_offset] >> 2)];
			current_bit_offset = 6;
			break;
		case 6:
			dst[dst_byte_offset++] =
				portable_filename_chars[
					(((src[src_byte_offset] & 0x3) << 4)
					 | (src[src_byte_offset + 1] >> 4))];
			current_bit_offset = 4;
			break;
		case 4:
			dst[dst_byte_offset++] =
				portable_filename_chars[
					(((src[src_byte_offset] & 0xF) << 2)
					 | (src[src_byte_offset + 1] >> 6))];
			current_bit_offset = 2;
			break;
		case 2:
			dst[dst_byte_offset++] =
				portable_filename_chars[
					(src[src_byte_offset] & 0x3F)];
			current_bit_offset = 0;
			break;
		}
		src_bit_offset += 6;
	}
	switch (current_bit_offset) {
	case 6:
		dst[dst_byte_offset] = portable_filename_chars[
			((src[src_byte_offset] & 0x3) << 4)];
		break;
	case 4:
		dst[dst_byte_offset] = portable_filename_chars[
			((src[src_byte_offset] & 0xF) << 2)];
		break;
	case 2:
		dst[dst_byte_offset] = portable_filename_chars[
			(src[src_byte_offset] & 0x3F)];
		break;
	}
	dst[dst_byte_offset] = '\0';
	(*dst_size) = dst_byte_offset;
out:
	return rc;
}

int ecryptfs_decode_from_filename(char *dst, size_t *dst_size, char *src,
				  size_t src_size)
{
	size_t src_byte_offset = 0;
	size_t dst_byte_offset = 0;
	u8 current_bit_offset = 0;
	int rc = 0;

	while (src_byte_offset < src_size) {
		src[src_byte_offset] = filename_rev_map[src[src_byte_offset]];
		switch (current_bit_offset) {
		case 0:
			dst[dst_byte_offset] = (src[src_byte_offset] << 2);
			current_bit_offset = 6;
			break;
		case 6:
			dst[dst_byte_offset++] |= (src[src_byte_offset] >> 4);
			dst[dst_byte_offset] = ((src[src_byte_offset] & 0xF)
						 << 4);
			current_bit_offset = 4;
			break;
		case 4:
			dst[dst_byte_offset++] |= (src[src_byte_offset] >> 2);
			dst[dst_byte_offset] = (src[src_byte_offset] << 6);
			current_bit_offset = 2;
			break;
		case 2:
			dst[dst_byte_offset++] |= (src[src_byte_offset]);
			dst[dst_byte_offset] = 0;
			current_bit_offset = 0;
			break;
		}
		src_byte_offset++;
	}
	(*dst_size) = dst_byte_offset;
out:
	return rc;
}



char *str = "This is a test of the eCryptfs packet encoding code. If this were an actual chunk of kernel code, your video card would spout 6-inch flames and your neighbor's inodes would flash your television's BIOS.";

int main()
{
	char enc[1024];
	char dec[1024];
	size_t enc_size;
	size_t dec_size;
	int i;
	int rc = 0;

	ecryptfs_encode_for_filename(enc, &enc_size, str, strlen(str));
	ecryptfs_decode_from_filename(dec, &dec_size, enc, enc_size);
	printf("%s\n", dec);
out:
	return rc;
}
