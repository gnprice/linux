/*
 * Skein: block cipher, hash function, and other uses
 *
 * Adapted by Greg Price <price@mit.edu> in 2013 from the version by
 * Daniel J. Bernstein in SUPERCOP, derived from the implementation by
 * Doug Whiting in the Skein submission for SHA-3.
 * All code by those authors in this file is in the public domain.
 */

#include <linux/bitops.h>
#include <linux/string.h>
#include <linux/types.h>
#include <asm/byteorder.h>

#define MK_64(hi32, lo32)  ((lo32) + (((uint64_t) (hi32)) << 32))

#define SKEIN_VERSION           (1)
#define SKEIN_ID_STRING_LE      (0x33414853)
#define SKEIN_SCHEMA_VER        MK_64(SKEIN_VERSION, SKEIN_ID_STRING_LE)
#define SKEIN_KS_PARITY         MK_64(0x1BD11BDA, 0xA9FC1A22)

static const uint64_t IV[] = {
	MK_64(0x4903ADFF, 0x749C51CE),
	MK_64(0x0D95DE39, 0x9746DF03),
	MK_64(0x8FD19341, 0x27C79BCE),
	MK_64(0x9A255629, 0xFF352CB1),
	MK_64(0x5DB62599, 0xDF6CA7B0),
	MK_64(0xEABE394C, 0xA9D5C3F4),
	MK_64(0x991112C7, 0x1A75B523),
	MK_64(0xAE18A40B, 0x660FCC33)
};

enum {
	R_512_0_0 = 46, R_512_0_1 = 36, R_512_0_2 = 19, R_512_0_3 = 37,
	R_512_1_0 = 33, R_512_1_1 = 27, R_512_1_2 = 14, R_512_1_3 = 42,
	R_512_2_0 = 17, R_512_2_1 = 49, R_512_2_2 = 36, R_512_2_3 = 39,
	R_512_3_0 = 44, R_512_3_1 =  9, R_512_3_2 = 54, R_512_3_3 = 56,
	R_512_4_0 = 39, R_512_4_1 = 30, R_512_4_2 = 34, R_512_4_3 = 24,
	R_512_5_0 = 13, R_512_5_1 = 50, R_512_5_2 = 10, R_512_5_3 = 17,
	R_512_6_0 = 25, R_512_6_1 = 29, R_512_6_2 = 39, R_512_6_3 = 43,
	R_512_7_0 =  8, R_512_7_1 = 35, R_512_7_2 = 56, R_512_7_3 = 22,
};

#define KW_TWK_BASE     (0)
#define KW_KEY_BASE     (3)
#define ks              (kw + KW_KEY_BASE)
#define ts              (kw + KW_TWK_BASE)

void threefish_block_encrypt(const uint64_t *key,
			     uint64_t tweak_low, uint64_t tweak_high,
			     const uint8_t *in,
			     uint64_t *out)
{
	uint64_t  kw[12];       /* key schedule words : chaining vars + tweak */
	uint64_t  X0, X1, X2, X3, X4, X5, X6, X7;  /* local copies, for speed */

	ts[0] = tweak_low;
	ts[1] = tweak_high;

	ks[0] = key[0];
	ks[1] = key[1];
	ks[2] = key[2];
	ks[3] = key[3];
	ks[4] = key[4];
	ks[5] = key[5];
	ks[6] = key[6];
	ks[7] = key[7];
	ks[8] = ks[0] ^ ks[1] ^ ks[2] ^ ks[3] ^
		ks[4] ^ ks[5] ^ ks[6] ^ ks[7] ^ SKEIN_KS_PARITY;

	ts[2] = ts[0] ^ ts[1];

	X0   = le64_to_cpu(((uint64_t *)in)[0]) + ks[0];
	X1   = le64_to_cpu(((uint64_t *)in)[1]) + ks[1];
	X2   = le64_to_cpu(((uint64_t *)in)[2]) + ks[2];
	X3   = le64_to_cpu(((uint64_t *)in)[3]) + ks[3];
	X4   = le64_to_cpu(((uint64_t *)in)[4]) + ks[4];
	X5   = le64_to_cpu(((uint64_t *)in)[5]) + ks[5] + ts[0];
	X6   = le64_to_cpu(((uint64_t *)in)[6]) + ks[6] + ts[1];
	X7   = le64_to_cpu(((uint64_t *)in)[7]) + ks[7];

#define R512(p0, p1, p2, p3, p4, p5, p6, p7, ROT, rNum) do {           \
	X##p0 += X##p1; X##p1 = rol64(X##p1, ROT##_0); X##p1 ^= X##p0; \
	X##p2 += X##p3; X##p3 = rol64(X##p3, ROT##_1); X##p3 ^= X##p2; \
	X##p4 += X##p5; X##p5 = rol64(X##p5, ROT##_2); X##p5 ^= X##p4; \
	X##p6 += X##p7; X##p7 = rol64(X##p7, ROT##_3); X##p7 ^= X##p6; \
	} while (0)

#define I512(R) do {                                                    \
	X0   += ks[((R)+1) % 9];   /* inject the key schedule value */  \
	X1   += ks[((R)+2) % 9];                                        \
	X2   += ks[((R)+3) % 9];                                        \
	X3   += ks[((R)+4) % 9];                                        \
	X4   += ks[((R)+5) % 9];                                        \
	X5   += ks[((R)+6) % 9] + ts[((R)+1) % 3];                      \
	X6   += ks[((R)+7) % 9] + ts[((R)+2) % 3];                      \
	X7   += ks[((R)+8) % 9] +     (R)+1;                            \
	} while (0)

#define R512_8_rounds(R) do {                             \
	R512(0, 1, 2, 3, 4, 5, 6, 7, R_512_0, 8*(R)+1);   \
	R512(2, 1, 4, 7, 6, 5, 0, 3, R_512_1, 8*(R)+2);	  \
	R512(4, 1, 6, 3, 0, 5, 2, 7, R_512_2, 8*(R)+3);	  \
	R512(6, 1, 0, 7, 2, 5, 4, 3, R_512_3, 8*(R)+4);	  \
	I512(2*(R));					  \
	R512(0, 1, 2, 3, 4, 5, 6, 7, R_512_4, 8*(R)+5);	  \
	R512(2, 1, 4, 7, 6, 5, 0, 3, R_512_5, 8*(R)+6);	  \
	R512(4, 1, 6, 3, 0, 5, 2, 7, R_512_6, 8*(R)+7);	  \
	R512(6, 1, 0, 7, 2, 5, 4, 3, R_512_7, 8*(R)+8);	  \
	I512(2*(R)+1);					  \
	} while (0)

	R512_8_rounds(0);
	R512_8_rounds(1);
	R512_8_rounds(2);
	R512_8_rounds(3);
	R512_8_rounds(4);
	R512_8_rounds(5);
	R512_8_rounds(6);
	R512_8_rounds(7);
	R512_8_rounds(8);

	out[0] = X0;
	out[1] = X1;
	out[2] = X2;
	out[3] = X3;
	out[4] = X4;
	out[5] = X5;
	out[6] = X6;
	out[7] = X7;
}

void skein_ubi(const uint64_t *key,
	       uint64_t tweak_low, uint64_t tweak_high,
	       const unsigned char *in,
	       unsigned long long inlen,
	       uint64_t *out)
{
	uint8_t buf[64];
	int i;

	memmove(out, key, 64);

	tweak_high |= ((uint64_t) 64) << 56;
	while (inlen > 64) {
		tweak_low += 64;
		threefish_block_encrypt(out, tweak_low, tweak_high, (uint64_t *)in, out);
		for (i = 0; i < 8; i++)
			out[i] ^= le64_to_cpu(((uint64_t *)in)[i]);
		in += 64;
		inlen -= 64;
		tweak_high &= ~(((uint64_t) 64) << 56);
	}

	memset(buf, 0, sizeof(buf));
	if (inlen)
		memmove(buf, in, inlen);
	tweak_low += inlen;
	tweak_high |= ((uint64_t) 128) << 56;
	threefish_block_encrypt(out, tweak_low, tweak_high, (uint64_t *)buf, out);
	for (i = 0; i < 8; i++)
		out[i] ^= le64_to_cpu(((uint64_t *)buf)[i]);
}

void skein_output(const uint64_t *state,
		  uint8_t *out,
		  int out_blocks)
{
	uint64_t tweak_low, tweak_high;
	uint8_t buf[8];
	int block;

	tweak_low = 0;
	tweak_high = ((uint64_t) 63) << 56;
	for (block = 0; block < out_blocks; block++) {
		*(uint64_t *)buf = cpu_to_le64(block);
		skein_ubi(state, tweak_low, tweak_high, buf, 8, out);
		out += 64;
	}
}

int skein_hash(unsigned char *out,
	       const unsigned char *in,
	       unsigned long long inlen)
{
	uint64_t state[8];
	uint64_t tweak_low, tweak_high;
	uint8_t buf[64];
	int i;

	memcpy(state, IV, sizeof(state));

	tweak_low = 0;
	tweak_high = ((uint64_t) 48) << 56;
	skein_ubi(state, tweak_low, tweak_high, in, inlen, state);

	skein_output(state, state, 1);

	for (i = 0; i < 8; i++)
		((uint64_t *)out)[i] = cpu_to_le64(state[i]);

	return 0;
}
