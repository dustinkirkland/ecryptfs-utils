#include <stdio.h>
#include <string.h>
#include <errno.h>

#define u8 unsigned char

/**
 * Temporary holding place for functions relating to filename
 * encryption
 */

/* 64 characters forming a 6-bit target field */
static unsigned char *portable_filename_chars = ("-.0123456789ABCD"
						 "EFGHIJKLMNOPQRST"
						 "UVWXYZabcdefghij"
						 "klmnopqrstuvwxyz");

static unsigned char filename_rev_map[] = {
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 7 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 15 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 23 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 31 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 39 */
	0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, /* 47 */
	0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, /* 55 */
	0x0A, 0x0B, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, /* 63 */
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
int ecryptfs_encode_for_filename(unsigned char *dst, size_t *dst_size,
				 unsigned char *src, size_t src_size)
{
	size_t num_blocks;
	size_t block_num = 0;
	unsigned char last_block[3];
	size_t dst_offset = 0;
	int rc = 0;

	if (src_size == 0) {
		rc = -EINVAL;
		goto out;
	}
	num_blocks = (src_size / 3);
	if ((src_size % 3) == 0) {
		memcpy(last_block, (&src[src_size - 3]), 3);
	} else {
		num_blocks++;
		last_block[2] = 0x00;
		switch(src_size % 3) {
		case 1:
			last_block[0] = src[src_size - 1];
			last_block[1] = 0x00;
			break;
		case 2:
			last_block[0] = src[src_size - 2];
			last_block[1] = src[src_size - 1];
		}
	}
	(*dst_size) = (num_blocks * 4);
	if (!dst)
		goto out;
	while (block_num < num_blocks) {
		unsigned char *src_block;
		unsigned char dst_block[4];

		if (block_num == (num_blocks - 1))
			src_block = last_block;
		else
			src_block = &src[block_num * 3];
		dst_block[0] = ((src_block[0] >> 2) & 0x3f);
		dst_block[1] = (((src_block[0] << 4) & 0x30)
				| ((src_block[1] >> 4) & 0x0f));
		dst_block[2] = (((src_block[1] << 2) & 0x3c)
				| ((src_block[2] >> 6) & 0x03));
		dst_block[3] = (src_block[2] & 0x3f);
		dst[dst_offset++] = portable_filename_chars[dst_block[0]];
		dst[dst_offset++] = portable_filename_chars[dst_block[1]];
		dst[dst_offset++] = portable_filename_chars[dst_block[2]];
		dst[dst_offset++] = portable_filename_chars[dst_block[3]];
		block_num++;
	}
out:
	return rc;
}

int ecryptfs_decode_from_filename(unsigned char *dst, size_t *dst_size,
				  unsigned char *src, size_t src_size)
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



/* char *str = "This is a test of the eCryptfs packet encoding
 * code. If this were an actual chunk of kernel code, your video card
 * would spout 6-inch flames and your neighbor's inodes would flash
 * your television's BIOS."; */

unsigned char str[43] = { 0x46, 0x29, 0x7f, 0xa0, 0x6f, 0x4b, 0x66, 0xfc,
			  0xde, 0x02, 0x07, 0xf8, 0x31, 0x61, 0xb2, 0xee,
			  0x65, 0x9e, 0x68, 0xdf, 0x81, 0x0b, 0x54, 0x70,
			  0x0c, 0x2c, 0xe6, 0xf4, 0x79, 0xb7, 0xd3, 0xbf,
			  0xa5, 0x96, 0x11, 0x11, 0xf5, 0xc1, 0x5b, 0x87,
			  0x16, 0x4e, 0xed };

/*unsigned char encoded[61] = {
0x46, 0x29, 0x7f, 0xa0, 0x6f, 0x4b, 0x66, 0xfc, 0xde, 0x02, 0x07, 0xaf, 0x33, 0xdc, 0xf4, 0xfd, 
0xa1, 0x40, 0xf2, 0x77, 0x86, 0xfa, 0x86, 0xbc, 0x48, 0xed, 0x26, 0x75, 0xc2, 0x9a, 0x7d, 0xf7, 
0x42, 0x27, 0xfe, 0x55, 0xa7, 0x4e, 0x3b, 0x4a, 0xb3, 0x2a, 0xc7, 0x00, 0x00

}; */

unsigned char *encoded = "";

int main()
{
	char enc[1024];
	char dec[1024];
	size_t enc_size;
	size_t dec_size;
	int i;
	int rc = 0;

	ecryptfs_encode_for_filename(NULL, &enc_size, str, 43);
	printf("enc_size = [%d]\n", enc_size);
	ecryptfs_encode_for_filename(enc, &enc_size, str, 43);
	enc[enc_size] = '\0';
	printf("Encoded: [%s]\n", enc);
	ecryptfs_decode_from_filename(dec, &dec_size, enc, enc_size);
	printf("Decoded:\n");
	for (i = 0; i < dec_size; i++) {
		if ((i % 16) == 0)
			printf("\n");
		printf("0x%.2x.", (unsigned char)dec[i]);
	}
	printf("\n");
out:
	return rc;
}
