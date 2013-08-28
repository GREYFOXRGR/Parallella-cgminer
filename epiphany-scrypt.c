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

#include <stdint.h>
#include <string.h>

#include "e_lib.h"
#include "epiphany_mailbox.h"

#define TMTO_RATIO 5
#define SCRATCHBUF_SIZE	(((1024 + TMTO_RATIO - 1) / TMTO_RATIO) * 128)

// This aproximation to division works fine up to a = 43694
#define DIVTMTO(a) ((26215 * (a))>>17) // If TMTO_RATIO changes you need redefine this macro

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

/* SHA256 constants */
static const uint32_t sha256_c[64] = {
	0x428a2f98,
	0x71374491,
	0xb5c0fbcf,
	0xe9b5dba5,
	0x3956c25b,
	0x59f111f1,
	0x923f82a4,
	0xab1c5ed5,
	0xd807aa98,
	0x12835b01,
	0x243185be,
	0x550c7dc3,
	0x72be5d74,
	0x80deb1fe,
	0x9bdc06a7,
	0xc19bf174,
	0xe49b69c1,
	0xefbe4786,
	0x0fc19dc6,
	0x240ca1cc,
	0x2de92c6f,
	0x4a7484aa,
	0x5cb0a9dc,
	0x76f988da,
	0x983e5152,
	0xa831c66d,
	0xb00327c8,
	0xbf597fc7,
	0xc6e00bf3,
	0xd5a79147,
	0x06ca6351,
	0x14292967,
	0x27b70a85,
	0x2e1b2138,
	0x4d2c6dfc,
	0x53380d13,
	0x650a7354,
	0x766a0abb,
	0x81c2c92e,
	0x92722c85,
	0xa2bfe8a1,
	0xa81a664b,
	0xc24b8b70,
	0xc76c51a3,
	0xd192e819,
	0xd6990624,
	0xf40e3585,
	0x106aa070,
	0x19a4c116,
	0x1e376c08,
	0x2748774c,
	0x34b0bcb5,
	0x391c0cb3,
	0x4ed8aa4a,
	0x5b9cca4f,
	0x682e6ff3,
	0x748f82ee,
	0x78a5636f,
	0x84c87814,
	0x8cc70208,
	0x90befffa,
	0xa4506ceb,
	0xbef9a3f7,
	0xc67178f2
};

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
#define RNDr(S, W, i, k)			\
{						\
	RND(S[(64 - i) & 7], S[(65 - i) & 7],	\
	    S[(66 - i) & 7], S[(67 - i) & 7],	\
	    S[(68 - i) & 7], S[(69 - i) & 7],	\
	    S[(70 - i) & 7], S[(71 - i) & 7],	\
	    W[i] + k)				\
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
		memcpy(W, block, 64);
	for (i = 16; i < 64; i += 2) {
		W[i] = s1(W[i - 2]) + W[i - 7] + s0(W[i - 15]) + W[i - 16];
		W[i+1] = s1(W[i - 1]) + W[i - 6] + s0(W[i - 14]) + W[i - 15];
	}

	/* 2. Initialize working variables. */
	memcpy(S, state, 32);

	/* 3. Mix. */
	for (i = 0; i < 64; i++)
		RNDr(S, W, i, sha256_c[i]);

	/* 4. Mix local working variables into global state */
	for (i = 0; i < 8; i++)
		state[i] += S[i];
}

static inline void
SHA256_InitState(uint32_t * state)
{
	/* Magic initialization constants */
	static const uint32_t sha256_i[8] = {
		0x6A09E667,
		0xBB67AE85,
		0x3C6EF372,
		0xA54FF53A,
		0x510E527F,
		0x9B05688C,
		0x1F83D9AB,
		0x5BE0CD19
	};
	memcpy(state, sha256_i, 32);
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
	memcpy(pad, passwd+16, 16);
	memcpy(pad+4, passwdpad, 48);
	SHA256_Transform(tstate, pad, 1);
	memcpy(ihash, tstate, 32);

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
	memcpy(PShoctx.buf+8, outerpad, 32);

	/* Iterate through the blocks. */
	for (i = 0; i < 4; i++) {
		uint32_t istate[8];
		uint32_t ostate[8];

		memcpy(istate, PShictx.state, 32);
		PShictx.buf[4] = i + 1;
		SHA256_Transform(istate, PShictx.buf, 0);
		memcpy(PShoctx.buf, istate, 32);

		memcpy(ostate, PShoctx.state, 32);
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
	memcpy(pad, passwd+16, 16);
	memcpy(pad+4, passwdpad, 48);
	SHA256_Transform(tstate, pad, 1);
	memcpy(ihash, tstate, 32);

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
	memcpy(pad, tstate, 32);
	memcpy(pad+8, outerpad, 32);

	/* Feed the inner hash to the outer SHA256 operation. */
	SHA256_Transform(ostate, pad, 0);
}

/**
 * salsa20_8(B):
 * Apply the salsa20/8 core to the provided block.
 */
static inline void
salsa20_8(const uint32_t B[16], const uint32_t Bx[16], uint32_t Bout[16])
{
	size_t i;
	uint32_t Bor[16];

	Bor[ 0] = Bout[ 0] = (B[ 0] ^ Bx[ 0]);
	Bor[ 1] = Bout[ 1] = (B[ 1] ^ Bx[ 1]);
	Bor[ 2] = Bout[ 2] = (B[ 2] ^ Bx[ 2]);
	Bor[ 3] = Bout[ 3] = (B[ 3] ^ Bx[ 3]);
	Bor[ 4] = Bout[ 4] = (B[ 4] ^ Bx[ 4]);
	Bor[ 5] = Bout[ 5] = (B[ 5] ^ Bx[ 5]);
	Bor[ 6] = Bout[ 6] = (B[ 6] ^ Bx[ 6]);
	Bor[ 7] = Bout[ 7] = (B[ 7] ^ Bx[ 7]);
	Bor[ 8] = Bout[ 8] = (B[ 8] ^ Bx[ 8]);
	Bor[ 9] = Bout[ 9] = (B[ 9] ^ Bx[ 9]);
	Bor[10] = Bout[10] = (B[10] ^ Bx[10]);
	Bor[11] = Bout[11] = (B[11] ^ Bx[11]);
	Bor[12] = Bout[12] = (B[12] ^ Bx[12]);
	Bor[13] = Bout[13] = (B[13] ^ Bx[13]);
	Bor[14] = Bout[14] = (B[14] ^ Bx[14]);
	Bor[15] = Bout[15] = (B[15] ^ Bx[15]);
	for (i = 0; i < 8; i += 2) {
#define R(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
		/* Operate on columns. */
		Bout[ 4] ^= R(Bout[ 0]+Bout[12], 7);	Bout[ 9] ^= R(Bout[ 5]+Bout[ 1], 7);	Bout[14] ^= R(Bout[10]+Bout[ 6], 7);	Bout[ 3] ^= R(Bout[15]+Bout[11], 7);
		Bout[ 8] ^= R(Bout[ 4]+Bout[ 0], 9);	Bout[13] ^= R(Bout[ 9]+Bout[ 5], 9);	Bout[ 2] ^= R(Bout[14]+Bout[10], 9);	Bout[ 7] ^= R(Bout[ 3]+Bout[15], 9);
		Bout[12] ^= R(Bout[ 8]+Bout[ 4],13);	Bout[ 1] ^= R(Bout[13]+Bout[ 9],13);	Bout[ 6] ^= R(Bout[ 2]+Bout[14],13);	Bout[11] ^= R(Bout[ 7]+Bout[ 3],13);
		Bout[ 0] ^= R(Bout[12]+Bout[ 8],18);	Bout[ 5] ^= R(Bout[ 1]+Bout[13],18);	Bout[10] ^= R(Bout[ 6]+Bout[ 2],18);	Bout[15] ^= R(Bout[11]+Bout[ 7],18);

		/* Operate on rows. */
		Bout[ 1] ^= R(Bout[ 0]+Bout[ 3], 7);	Bout[ 6] ^= R(Bout[ 5]+Bout[ 4], 7);	Bout[11] ^= R(Bout[10]+Bout[ 9], 7);	Bout[12] ^= R(Bout[15]+Bout[14], 7);
		Bout[ 2] ^= R(Bout[ 1]+Bout[ 0], 9);	Bout[ 7] ^= R(Bout[ 6]+Bout[ 5], 9);	Bout[ 8] ^= R(Bout[11]+Bout[10], 9);	Bout[13] ^= R(Bout[12]+Bout[15], 9);
		Bout[ 3] ^= R(Bout[ 2]+Bout[ 1],13);	Bout[ 4] ^= R(Bout[ 7]+Bout[ 6],13);	Bout[ 9] ^= R(Bout[ 8]+Bout[11],13);	Bout[14] ^= R(Bout[13]+Bout[12],13);
		Bout[ 0] ^= R(Bout[ 3]+Bout[ 2],18);	Bout[ 5] ^= R(Bout[ 4]+Bout[ 7],18);	Bout[10] ^= R(Bout[ 9]+Bout[ 8],18);	Bout[15] ^= R(Bout[14]+Bout[13],18);
#undef R
	}
	Bout[ 0] += Bor[ 0];
	Bout[ 1] += Bor[ 1];
	Bout[ 2] += Bor[ 2];
	Bout[ 3] += Bor[ 3];
	Bout[ 4] += Bor[ 4];
	Bout[ 5] += Bor[ 5];
	Bout[ 6] += Bor[ 6];
	Bout[ 7] += Bor[ 7];
	Bout[ 8] += Bor[ 8];
	Bout[ 9] += Bor[ 9];
	Bout[10] += Bor[10];
	Bout[11] += Bor[11];
	Bout[12] += Bor[12];
	Bout[13] += Bor[13];
	Bout[14] += Bor[14];
	Bout[15] += Bor[15];
}

static char scratchpad[SCRATCHBUF_SIZE] __attribute__ ((aligned(8)));

/* cpu and memory intensive function to transform a 80 byte buffer into a 32 byte output
   scratchpad size needs to be at least 63 + (128 * r * p) + (256 * r + 64) + (128 * r * N) bytes
 */
static inline void scrypt_1024_1_1_256_sp(const uint32_t* input, uint32_t *ostate)
{
	uint32_t * V, *X, *Z, *Y;
	uint32_t V_TMP[64] __attribute__ ((aligned(8)));
	uint32_t i;
	uint32_t j;
	uint32_t k;

	X = V = (uint32_t *) scratchpad;

	PBKDF2_SHA256_80_128(input, X);

	for (i = 0; i < 1024; i++) {
		uint32_t ibase = DIVTMTO(i+1);
		if (!((i+1) - ibase * TMTO_RATIO))
			Y = &V[ibase * 32];
		else
			Y = &V_TMP[32*((i+1) & 1)];

		salsa20_8(&X[ 0], &X[16], &Y[ 0]);
		salsa20_8(&X[16], &Y[ 0], &Y[16]);
		X = Y;
	}

	for (i = 0; i < 1024; i++) {
		j = X[16] & 1023;

		uint32_t jbase = DIVTMTO(j);
		uint32_t jmod = j - jbase * TMTO_RATIO;
		uint32_t Vz_TMP[64] __attribute__ ((aligned(8)));

		Z  = &V[jbase * 32];
		while (jmod--) {
			Y = &Vz_TMP[32*((jmod+1) & 1)];
			salsa20_8(&Z[ 0], &Z[16], &Y[ 0]);
			salsa20_8(&Z[16], &Y[ 0], &Y[16]);
			Z = Y;
		}

		for(k = 0; k < 32; k++)
			V_TMP[k] = X[k] ^ Z[k];

		X = &V_TMP[0];
		Y = &V_TMP[32];

		salsa20_8(&X[ 0], &X[16], &Y[0]);
		salsa20_8(&X[16], &Y[0], &Y[16]);
		X = Y;
	}

	PBKDF2_SHA256_80_128_32(input, X, ostate);
}

__attribute__ ((noreturn))
int main(void) {

	uint32_t core_n = e_group_config.core_row * e_group_config.group_cols
			+ e_group_config.core_col;
	uint32_t ostate[8];

	while (1) {
		while (M[core_n].go == 0);
		scrypt_1024_1_1_256_sp(M[core_n].data, ostate);
		M[core_n].go = 0;
		M[core_n].ostate = ostate[7];
		M[core_n].working = 0;
	}
}

/* Save ~300 bytes by getting rid of the real exit() */
__attribute__ ((noreturn))
void exit(int status) { while(1) continue; }
