/*-
 * Copyright 2009 Colin Percival,
 * Copyright 2011 ArtForz,
 * Copyright 2013 Rafael Waldo Delgado Doblas,
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * This file was originally written by Colin Percival as part of the Tarsnap
 * online backup system.
 *
 * Rafael Waldo Delgado Doblas implemented the tmto exploit based on
 * Alexander Peslyak idea.
 */

//#include <errno.h>
#include <stdint.h>
//#include <stdlib.h>
#include <string.h>

#include "e_lib.h"
#include "epiphany_mailbox.h"

/* 131583 rounded up to 4 byte alignment */
/* 63 + (128) + (256 + 64) = 511 */

// ((1023 / TMTO_RATIO) + 1) * 128

#define SCRATCHBUF_SIZE	22464
#define TMTO_RATIO 6 // Must be > 0

volatile shared_buf_t M[16] SECTION("shared_dram");

#define	bswap_16(value)  \
 	((((value) & 0xff) << 8) | ((value) >> 8))

#define	bswap_32(value)	\
 	(((uint32_t)bswap_16((uint16_t)((value) & 0xffff)) << 16) | \
 	(uint32_t)bswap_16((uint16_t)((value) >> 16)))

/* This assumes htobe32 is a macro in endian.h, and if it doesn't exist, then
 * htobe64 also won't exist */
#ifndef htobe32
# if __BYTE_ORDER == __LITTLE_ENDIAN
#  define htobe32(x) bswap_32(x)
# elif __BYTE_ORDER == __BIG_ENDIAN
#  define htobe32(x) (x)
#endif
#endif


static void
blkcpy(uint32_t * dest, const uint32_t * src, size_t len)
{
	size_t i;

	for (i = 0; i < len; i++)
		dest[i] = src[i];
}

typedef struct SHA256Context {
	uint32_t state[8];
	uint32_t buf[16];
} SHA256_CTX;

/*
 * Encode a length len/4 vector of (uint32_t) into a length len vector of
 * (unsigned char) in big-endian form.  Assumes len is a multiple of 4.
 */
static inline void
be32enc_vect(uint32_t *dst, const uint32_t *src, uint32_t len)
{
	uint32_t i;

	for (i = 0; i < len; i++)
		dst[i] = htobe32(src[i]);
}

/* Elementary functions used by SHA256 */
#define Ch(x, y, z)	((x & (y ^ z)) ^ z)
#define Maj(x, y, z)	((x & (y | z)) | (y & z))
#define SHR(x, n)	(x >> n)
#define ROTR(x, n)	((x >> n) | (x << (32 - n)))
#define S0(x)		(ROTR(x, 2) ^ ROTR(x, 13) ^ ROTR(x, 22))
#define S1(x)		(ROTR(x, 6) ^ ROTR(x, 11) ^ ROTR(x, 25))
#define s0(x)		(ROTR(x, 7) ^ ROTR(x, 18) ^ SHR(x, 3))
#define s1(x)		(ROTR(x, 17) ^ ROTR(x, 19) ^ SHR(x, 10))

/* SHA256 round function */
#define RND(a, b, c, d, e, f, g, h, k)			\
	t0 = h + S1(e) + Ch(e, f, g) + k;		\
	t1 = S0(a) + Maj(a, b, c);			\
	d += t0;					\
	h  = t0 + t1;

/* Adjusted round function for rotating state */
// #define RNDr(S, W, i, k)			\
// 	RND(S[(64 - i) % 8], S[(65 - i) % 8],	\
// 	    S[(66 - i) % 8], S[(67 - i) % 8],	\
// 	    S[(68 - i) % 8], S[(69 - i) % 8],	\
// 	    S[(70 - i) % 8], S[(71 - i) % 8],	\
// 	    W[i] + k)

static void
RNDr (uint32_t *S, uint32_t *W, int i, uint32_t k) {
	uint32_t t0, t1;
	RND(S[(64 - i) % 8], S[(65 - i) % 8],
	    S[(66 - i) % 8], S[(67 - i) % 8],
	    S[(68 - i) % 8], S[(69 - i) % 8],
	    S[(70 - i) % 8], S[(71 - i) % 8],
	    W[i] + k)
}
/*
 * SHA256 block compression function.  The 256-bit state is transformed via
 * the 512-bit input block to produce a new state.
 */
static void
SHA256_Transform(uint32_t * state, const uint32_t block[16], int swap)
{
	uint32_t W[64];
	uint32_t S[8];
	uint32_t t0, t1;
	int i;

	/* 1. Prepare message schedule W. */
	if(swap)
		for (i = 0; i < 16; i++)
			W[i] = htobe32(block[i]);
	else
		blkcpy(W, block, 16);
	for (i = 16; i < 64; i += 2) {
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	/* 2. Initialize working variables. */
	blkcpy(S, state, 8);

	/* 3. Mix. */
	RNDr(S, W, 0, 0x428a2f98);
	RNDr(S, W, 1, 0x71374491);
	RNDr(S, W, 2, 0xb5c0fbcf);
	RNDr(S, W, 3, 0xe9b5dba5);
	RNDr(S, W, 4, 0x3956c25b);
	RNDr(S, W, 5, 0x59f111f1);
	RNDr(S, W, 6, 0x923f82a4);
	RNDr(S, W, 7, 0xab1c5ed5);
	RNDr(S, W, 8, 0xd807aa98);
	RNDr(S, W, 9, 0x12835b01);
	RNDr(S, W, 10, 0x243185be);
	RNDr(S, W, 11, 0x550c7dc3);
	RNDr(S, W, 12, 0x72be5d74);
	RNDr(S, W, 13, 0x80deb1fe);
	RNDr(S, W, 14, 0x9bdc06a7);
	RNDr(S, W, 15, 0xc19bf174);
	RNDr(S, W, 16, 0xe49b69c1);
	RNDr(S, W, 17, 0xefbe4786);
	RNDr(S, W, 18, 0x0fc19dc6);
	RNDr(S, W, 19, 0x240ca1cc);
	RNDr(S, W, 20, 0x2de92c6f);
	RNDr(S, W, 21, 0x4a7484aa);
	RNDr(S, W, 22, 0x5cb0a9dc);
	RNDr(S, W, 23, 0x76f988da);
	RNDr(S, W, 24, 0x983e5152);
	RNDr(S, W, 25, 0xa831c66d);
	RNDr(S, W, 26, 0xb00327c8);
	RNDr(S, W, 27, 0xbf597fc7);
	RNDr(S, W, 28, 0xc6e00bf3);
	RNDr(S, W, 29, 0xd5a79147);
	RNDr(S, W, 30, 0x06ca6351);
	RNDr(S, W, 31, 0x14292967);
	RNDr(S, W, 32, 0x27b70a85);
	RNDr(S, W, 33, 0x2e1b2138);
	RNDr(S, W, 34, 0x4d2c6dfc);
	RNDr(S, W, 35, 0x53380d13);
	RNDr(S, W, 36, 0x650a7354);
	RNDr(S, W, 37, 0x766a0abb);
	RNDr(S, W, 38, 0x81c2c92e);
	RNDr(S, W, 39, 0x92722c85);
	RNDr(S, W, 40, 0xa2bfe8a1);
	RNDr(S, W, 41, 0xa81a664b);
	RNDr(S, W, 42, 0xc24b8b70);
	RNDr(S, W, 43, 0xc76c51a3);
	RNDr(S, W, 44, 0xd192e819);
	RNDr(S, W, 45, 0xd6990624);
	RNDr(S, W, 46, 0xf40e3585);
	RNDr(S, W, 47, 0x106aa070);
	RNDr(S, W, 48, 0x19a4c116);
	RNDr(S, W, 49, 0x1e376c08);
	RNDr(S, W, 50, 0x2748774c);
	RNDr(S, W, 51, 0x34b0bcb5);
	RNDr(S, W, 52, 0x391c0cb3);
	RNDr(S, W, 53, 0x4ed8aa4a);
	RNDr(S, W, 54, 0x5b9cca4f);
	RNDr(S, W, 55, 0x682e6ff3);
	RNDr(S, W, 56, 0x748f82ee);
	RNDr(S, W, 57, 0x78a5636f);
	RNDr(S, W, 58, 0x84c87814);
	RNDr(S, W, 59, 0x8cc70208);
	RNDr(S, W, 60, 0x90befffa);
	RNDr(S, W, 61, 0xa4506ceb);
	RNDr(S, W, 62, 0xbef9a3f7);
	RNDr(S, W, 63, 0xc67178f2);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];
}

static inline void
SHA256_InitState(uint32_t * state)
{
	/* Magic initialization constants */
	state[0] = 0x6A09E667;
	state[1] = 0xBB67AE85;
	state[2] = 0x3C6EF372;
	state[3] = 0xA54FF53A;
	state[4] = 0x510E527F;
	state[5] = 0x9B05688C;
	state[6] = 0x1F83D9AB;
	state[7] = 0x5BE0CD19;
}

static const uint32_t passwdpad[12] = {0x00000080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x80020000};
static const uint32_t outerpad[8] = {0x80000000, 0, 0, 0, 0, 0, 0, 0x00000300};

/**
 * PBKDF2_SHA256(passwd, passwdlen, salt, saltlen, c, buf, dkLen):
 * Compute PBKDF2(passwd, salt, c, dkLen) using HMAC-SHA256 as the PRF, and
 * write the output to buf.  The value dkLen must be at most 32 * (2^32 - 1).
 */
static inline void
PBKDF2_SHA256_80_128(const uint32_t * passwd, uint32_t * buf)
{
	SHA256_CTX PShictx, PShoctx;
	uint32_t tstate[8];
	uint32_t ihash[8];
	uint32_t i;
	uint32_t pad[16];

	static const uint32_t innerpad[11] = {0x00000080, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xa0040000};

	/* If Klen > 64, the key is really SHA256(K). */
	SHA256_InitState(tstate);
	SHA256_Transform(tstate, passwd, 1);
	blkcpy(pad, &passwd[4], 4);
	blkcpy(&pad[1], passwdpad, 12);
	SHA256_Transform(tstate, pad, 1);
	blkcpy(ihash, tstate, 8);

	SHA256_InitState(PShictx.state);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	SHA256_Transform(PShictx.state, pad, 0);
	SHA256_Transform(PShictx.state, passwd, 1);
	be32enc_vect(PShictx.buf, passwd+16, 4);
	be32enc_vect(PShictx.buf+5, innerpad, 11);

	SHA256_InitState(PShoctx.state);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	SHA256_Transform(PShoctx.state, pad, 0);
	blkcpy(&PShoctx.buf[2], outerpad, 4);

	/* Iterate through the blocks. */
	for (i = 0; i < 4; i++) {
		uint32_t istate[8];
		uint32_t ostate[8];

		blkcpy(istate, PShictx.state, 4);
		PShictx.buf[4] = i + 1;
		SHA256_Transform(istate, PShictx.buf, 0);
		blkcpy(PShoctx.buf, istate, 4);

		blkcpy(ostate, PShoctx.state, 4);
		SHA256_Transform(ostate, PShoctx.buf, 0);
		be32enc_vect(buf+i*8, ostate, 8);
	}
}


static inline void
PBKDF2_SHA256_80_128_32(const uint32_t * passwd, const uint32_t * salt, uint32_t *ostate)
{
	uint32_t tstate[8];
	uint32_t ihash[8];
	uint32_t i;

	/* Compute HMAC state after processing P and S. */
	uint32_t pad[16];

	static const uint32_t ihash_finalblk[16] = {0x00000001,0x80000000,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,0x00000620};

	/* If Klen > 64, the key is really SHA256(K). */
	SHA256_InitState(tstate);
	SHA256_Transform(tstate, passwd, 1);
	blkcpy(pad, &passwd[4], 4);
	blkcpy(&pad[1], passwdpad, 12);
	SHA256_Transform(tstate, pad, 1);
	blkcpy(ihash, tstate, 8);

	SHA256_InitState(ostate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x5c5c5c5c;
	for (; i < 16; i++)
		pad[i] = 0x5c5c5c5c;
	SHA256_Transform(ostate, pad, 0);

	SHA256_InitState(tstate);
	for (i = 0; i < 8; i++)
		pad[i] = ihash[i] ^ 0x36363636;
	for (; i < 16; i++)
		pad[i] = 0x36363636;
	SHA256_Transform(tstate, pad, 0);
	SHA256_Transform(tstate, salt, 1);
	SHA256_Transform(tstate, salt+16, 1);
	SHA256_Transform(tstate, ihash_finalblk, 0);
	blkcpy(pad, tstate, 8);
	blkcpy(&pad[2], outerpad, 8);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Transform(ostate, pad, 0);
}


static uint32_t
R (uint32_t a, uint32_t b)
{
	return (((a) << (b)) | ((a) >> (32 - (b))));
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static inline void
salsa20_8(const uint32_t *B, const uint32_t *Bx, uint32_t *Y)
{
	size_t i;

	Y[ 0] = B[ 0] ^ Bx[ 0];
	Y[ 1] = B[ 1] ^ Bx[ 1];
	Y[ 2] = B[ 2] ^ Bx[ 2];
	Y[ 3] = B[ 3] ^ Bx[ 3];
	Y[ 4] = B[ 4] ^ Bx[ 4];
	Y[ 5] = B[ 5] ^ Bx[ 5];
	Y[ 6] = B[ 6] ^ Bx[ 6];
	Y[ 7] = B[ 7] ^ Bx[ 7];
	Y[ 8] = B[ 8] ^ Bx[ 8];
	Y[ 9] = B[ 9] ^ Bx[ 9];
	Y[10] = B[10] ^ Bx[10];
	Y[11] = B[11] ^ Bx[11];
	Y[12] = B[12] ^ Bx[12];
	Y[13] = B[13] ^ Bx[13];
	Y[14] = B[14] ^ Bx[14];
	Y[15] = B[15] ^ Bx[15];
	for (i = 0; i < 8; i += 2) {
//#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		Y[ 4] ^= R(Y[ 0]+Y[12], 7);	Y[ 9] ^= R(Y[ 5]+Y[ 1], 7);	Y[14] ^= R(Y[10]+Y[ 6], 7);	Y[ 3] ^= R(Y[15]+Y[11], 7);
		Y[ 8] ^= R(Y[ 4]+Y[ 0], 9);	Y[13] ^= R(Y[ 9]+Y[ 5], 9);	Y[ 2] ^= R(Y[14]+Y[10], 9);	Y[ 7] ^= R(Y[ 3]+Y[15], 9);
		Y[12] ^= R(Y[ 8]+Y[ 4],13);	Y[ 1] ^= R(Y[13]+Y[ 9],13);	Y[ 6] ^= R(Y[ 2]+Y[14],13);	Y[11] ^= R(Y[ 7]+Y[ 3],13);
		Y[ 0] ^= R(Y[12]+Y[ 8],18);	Y[ 5] ^= R(Y[ 1]+Y[13],18);	Y[10] ^= R(Y[ 6]+Y[ 2],18);	Y[15] ^= R(Y[11]+Y[ 7],18);

		/* Operate on rows. */
		Y[ 1] ^= R(Y[ 0]+Y[ 3], 7);	Y[ 6] ^= R(Y[ 5]+Y[ 4], 7);	Y[11] ^= R(Y[10]+Y[ 9], 7);	Y[12] ^= R(Y[15]+Y[14], 7);
		Y[ 2] ^= R(Y[ 1]+Y[ 0], 9);	Y[ 7] ^= R(Y[ 6]+Y[ 5], 9);	Y[ 8] ^= R(Y[11]+Y[10], 9);	Y[13] ^= R(Y[12]+Y[15], 9);
		Y[ 3] ^= R(Y[ 2]+Y[ 1],13);	Y[ 4] ^= R(Y[ 7]+Y[ 6],13);	Y[ 9] ^= R(Y[ 8]+Y[11],13);	Y[14] ^= R(Y[13]+Y[12],13);
		Y[ 0] ^= R(Y[ 3]+Y[ 2],18);	Y[ 5] ^= R(Y[ 4]+Y[ 7],18);	Y[10] ^= R(Y[ 9]+Y[ 8],18);	Y[15] ^= R(Y[14]+Y[13],18);
//#undef R
	}
	Y[ 0] += B[ 0] ^ Bx[ 0];
	Y[ 1] += B[ 1] ^ Bx[ 1];
	Y[ 2] += B[ 2] ^ Bx[ 2];
	Y[ 3] += B[ 3] ^ Bx[ 3];
	Y[ 4] += B[ 4] ^ Bx[ 4];
	Y[ 5] += B[ 5] ^ Bx[ 5];
	Y[ 6] += B[ 6] ^ Bx[ 6];
	Y[ 7] += B[ 7] ^ Bx[ 7];
	Y[ 8] += B[ 8] ^ Bx[ 8];
	Y[ 9] += B[ 9] ^ Bx[ 9];
	Y[10] += B[10] ^ Bx[10];
	Y[11] += B[11] ^ Bx[11];
	Y[12] += B[12] ^ Bx[12];
	Y[13] += B[13] ^ Bx[13];
	Y[14] += B[14] ^ Bx[14];
	Y[15] += B[15] ^ Bx[15];
}

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
 */
static void scrypt_1024_1_1_256_sp(uint32_t* input, uint32_t *ostate)
{
	uint32_t * V;
	uint32_t * X;
	uint32_t * Y;
	uint32_t * Z;
	uint32_t TMTO_AUX[64];
	uint32_t i;
	uint32_t j;

	char scratchpad[SCRATCHBUF_SIZE];

	X = V = (uint32_t *)scratchpad;

	PBKDF2_SHA256_80_128(input, X);

	for (i = 1; i < 1023; i++) {
		if (!(i % TMTO_RATIO))
			Y = &V[(i/TMTO_RATIO) * 32];
		else
			Y = &TMTO_AUX[32*i%2];

		salsa20_8(&X[0], &X[16], &Y[0]);
		salsa20_8(&X[16], &Y[0], &Y[16]);

		X = Y;
	}
	for (i = 0; i < 1024; i++) {
		j = X[16] & 1023;

		uint32_t jbase = j / TMTO_RATIO;
		uint32_t jmod = j % TMTO_RATIO;

		Z = &V[jbase * 32];
		while (jmod--) {
			Y = &TMTO_AUX[32*jmod%2];
			salsa20_8(&Z[0], &Z[16], &Y[0]);
			salsa20_8(&Z[16], &Y[0], &Y[16]);
			Z = Y;
		}


		uint32_t X_XOR[64];
		for(j = 0; j < 32; j++)
			X_XOR[j] = X[j] ^ Z[j];

		salsa20_8(&X_XOR[0], &X_XOR[16], &X_XOR[32]);
		salsa20_8(&X_XOR[16], &X_XOR[32], &X_XOR[48]);
		X = &X_XOR[32];
	}

	PBKDF2_SHA256_80_128_32(input, X, ostate);
}

int main(void) {

	uint32_t core_n = e_group_config.core_row * e_group_config.group_cols
			+ e_group_config.core_col;
	uint32_t ostate[8];

	uint32_t input[20];

	while (1) {
		while (M[core_n].go == 0);

		uint8_t i;
		for (i = 0; i < 20; i++) {
			input[i] = M[core_n].data[i];
		}

		scrypt_1024_1_1_256_sp(input, ostate);
		M[core_n].go = 0;
		M[core_n].ostate = ostate[7];
		M[core_n].working = 0;
	}

	return 0;
}
