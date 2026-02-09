/*
 * SHA-512 / SHA-384 (FIPS 180-4)：手写算法源码，无外部库。
 * IV 低 32 位用于指纹: 0xf3bcc908, 0x84caa73b, 0xfe94f82b, 0x5f1d36f1,
 * 0xade682d1, 0x2b3e6c1f, 0xfb41bd6b, 0x137e2179.
 */
#include "SHA512.h"
#include <string.h>

#if defined(_MSC_VER) && _MSC_VER < 1920
typedef unsigned long long uint64_t;
#endif

static const uint64_t K[80] = {
	0x428a2f98d728ae22ULL, 0x7137449123ef65cdULL, 0xb5c0fbcfec4d3b2fULL, 0xe9b5dba58189dbbcULL,
	0x3956c25b348b5384ULL, 0x59f111f1b605d019ULL, 0x923f82a4af194f9bULL, 0xab1c5ed5da6d8118ULL,
	0xd807aa98a3030242ULL, 0x12835b0145706fbeULL, 0x243185be4ee4b28cULL, 0x550c7dc3d5ffb4e2ULL,
	0x72be5d74f27b896fULL, 0x80deb1fe3b1696b1ULL, 0x9bdc06a725c71235ULL, 0xc19bf174cf692694ULL,
	0xe49b69c19ef14ad2ULL, 0xefbe4786384f25e3ULL, 0x0fc19dc68b8cd5b5ULL, 0x240ca1cc77ac9c65ULL,
	0x2de92c6f592b0275ULL, 0x4a7484aa6ea6e483ULL, 0x5cb0a9dcbd41fbd4ULL, 0x76f988da831153b5ULL,
	0x983e5152ee66dfabULL, 0xa831c66d2db43210ULL, 0xb00327c898fb213fULL, 0xbf597fc7beef0ee4ULL,
	0xc6e00bf33da88fc2ULL, 0xd5a79147930aa725ULL, 0x06ca6351e003826fULL, 0x142929670a0e6e70ULL,
	0x27b70a8546d22ffcULL, 0x2e1b21385c26c926ULL, 0x4d2c6dfc5ac42aedULL, 0x53380d139d95b3dfULL,
	0x650a73548baf63deULL, 0x766a0abb3c77b2a8ULL, 0x81c2c92e47edaee6ULL, 0x92722c851482353bULL,
	0xa2bfe8a14cf10364ULL, 0xa81a664bbc423001ULL, 0xc24b8b70d0f89791ULL, 0xc76c51a30654be30ULL,
	0xd192e819d6ef5218ULL, 0xd69906245565a910ULL, 0xf40e35855771202aULL, 0x106aa07032bbd1b8ULL,
	0x19a4c116b8d2d0c8ULL, 0x1e376c085141ab53ULL, 0x2748774cdf8eeb99ULL, 0x34b0bcb5e19b48a8ULL,
	0x391c0cb3c5c95a63ULL, 0x4ed8aa4ae3418acbULL, 0x5b9cca4f7763e373ULL, 0x682e6ff3d6b2b8a3ULL,
	0x748f82ee5defb2fcULL, 0x78a5636f43172f60ULL, 0x84c87814a1f0ab72ULL, 0x8cc702081a6439ecULL,
	0x90befffa23631e28ULL, 0xa4506cebde82bde9ULL, 0xbef9a3f7b2c67915ULL, 0xc67178f2e372532bULL,
	0xca273eceea26619cULL, 0xd186b8c721c0c207ULL, 0xeada7dd6cde0eb1eULL, 0xf57d4f7fee6ed178ULL,
	0x06f067aa72176fbaULL, 0x0a637dc5a2c898a6ULL, 0x113f9804bef90daeULL, 0x1b710b35131c471bULL,
	0x28db77f523047d84ULL, 0x32caab7b40c72493ULL, 0x3c9ebe0a15c9bebcULL, 0x431d67c49c100d4cULL,
	0x4cc5d4becb3e42b6ULL, 0x597f299cfc657e2aULL, 0x5fcb6fab3ad6faecULL, 0x6c44198c4a475817ULL
};

#define ROTR64(x, n) (((x) >> (n)) | ((x) << (64 - (n))))
#define Ch(x,y,z) (((x) & (y)) ^ ((~(x)) & (z)))
#define Ma(x,y,z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))
#define S0(x) (ROTR64(x, 28) ^ ROTR64(x, 34) ^ ROTR64(x, 39))
#define S1(x) (ROTR64(x, 14) ^ ROTR64(x, 18) ^ ROTR64(x, 41))
#define G0(x) (ROTR64(x, 1) ^ ROTR64(x, 8) ^ ((x) >> 7))
#define G1(x) (ROTR64(x, 19) ^ ROTR64(x, 61) ^ ((x) >> 6))

static uint64_t read64be(const uint8_t *p)
{
	return ((uint64_t)p[0] << 56) | ((uint64_t)p[1] << 48) | ((uint64_t)p[2] << 40) | ((uint64_t)p[3] << 32)
	     | ((uint64_t)p[4] << 24) | ((uint64_t)p[5] << 16) | ((uint64_t)p[6] << 8) | (uint64_t)p[7];
}

static void write64be(uint8_t *p, uint64_t x)
{
	p[0] = (uint8_t)(x >> 56); p[1] = (uint8_t)(x >> 48); p[2] = (uint8_t)(x >> 40); p[3] = (uint8_t)(x >> 32);
	p[4] = (uint8_t)(x >> 24); p[5] = (uint8_t)(x >> 16); p[6] = (uint8_t)(x >> 8);  p[7] = (uint8_t)x;
}

static void sha512_block(sha512_context *ctx)
{
	uint64_t W[80];
	uint64_t a, b, c, d, e, f, g, h, t0, t1;
	size_t i;
	const uint8_t *buf = ctx->buf;

	for (i = 0; i < 16; i++) W[i] = read64be(buf + i * 8);
	for (i = 16; i < 80; i++) W[i] = G1(W[i-2]) + W[i-7] + G0(W[i-15]) + W[i-16];

	a = ctx->hash[0]; b = ctx->hash[1]; c = ctx->hash[2]; d = ctx->hash[3];
	e = ctx->hash[4]; f = ctx->hash[5]; g = ctx->hash[6]; h = ctx->hash[7];

	for (i = 0; i < 80; i++) {
		t0 = h + S1(e) + Ch(e,f,g) + K[i] + W[i];
		t1 = S0(a) + Ma(a,b,c);
		h = g; g = f; f = e; e = d + t0; d = c; c = b; b = a; a = t0 + t1;
	}

	ctx->hash[0] += a; ctx->hash[1] += b; ctx->hash[2] += c; ctx->hash[3] += d;
	ctx->hash[4] += e; ctx->hash[5] += f; ctx->hash[6] += g; ctx->hash[7] += h;
}

void sha512_init(sha512_context *ctx)
{
	if (!ctx) return;
	ctx->hash[0] = 0x6a09e667f3bcc908ULL;
	ctx->hash[1] = 0xbb67ae8584caa73bULL;
	ctx->hash[2] = 0x3c6ef372fe94f82bULL;
	ctx->hash[3] = 0xa54ff53a5f1d36f1ULL;
	ctx->hash[4] = 0x510e527fade682d1ULL;
	ctx->hash[5] = 0x9b05688c2b3e6c1fULL;
	ctx->hash[6] = 0x1f83d9abfb41bd6bULL;
	ctx->hash[7] = 0x5be0cd19137e2179ULL;
	ctx->bits[0] = ctx->bits[1] = 0;
	ctx->len = 0;
}

void sha384_init(sha512_context *ctx)
{
	if (!ctx) return;
	ctx->hash[0] = 0xcbbb9d5dc1059ed8ULL;
	ctx->hash[1] = 0x629a292a367cd507ULL;
	ctx->hash[2] = 0x9159015a3070dd17ULL;
	ctx->hash[3] = 0x152fecd8f70e5939ULL;
	ctx->hash[4] = 0x67332667ffc00b31ULL;
	ctx->hash[5] = 0x8eb44a8768581511ULL;
	ctx->hash[6] = 0xdb0c2e0d64f98fa7ULL;
	ctx->hash[7] = 0x47b5481dbefa4fa4ULL;
	ctx->bits[0] = ctx->bits[1] = 0;
	ctx->len = 0;
}

void sha512_hash(sha512_context *ctx, const void *data, size_t len)
{
	const uint8_t *p = (const uint8_t *)data;
	if (!ctx || !data) return;

	while (len) {
		size_t n = 128 - ctx->len;
		if (n > len) n = len;
		memcpy(ctx->buf + ctx->len, p, n);
		ctx->len += n;
		p += n;
		len -= n;
		if (ctx->len == 128) {
			ctx->bits[0] += (128 * 8);
			if (ctx->bits[0] < (128 * 8)) ctx->bits[1]++;
			sha512_block(ctx);
			ctx->len = 0;
		}
	}
}

void sha512_done(sha512_context *ctx, uint8_t *hash)
{
	uint64_t lo, hi;
	size_t i, j, bitlen;
	if (!ctx) return;

	/* total bit count = full blocks already counted + final partial block */
	bitlen = ctx->len * 8;
	lo = ctx->bits[0] + bitlen;
	hi = ctx->bits[1];
	if (lo < bitlen) hi++;

	j = ctx->len;
	ctx->buf[j++] = 0x80;
	for (; j < 112; j++) ctx->buf[j] = 0;
	if (j > 112) {
		for (i = j; i < 128; i++) ctx->buf[i] = 0;
		sha512_block(ctx);
		memset(ctx->buf, 0, 112);
	}
	write64be(ctx->buf + 112, hi);
	write64be(ctx->buf + 120, lo);
	sha512_block(ctx);

	if (hash) {
		for (i = 0; i < 8; i++) write64be(hash + i * 8, ctx->hash[i]);
	}
}

void sha512(const void *data, size_t len, uint8_t *hash)
{
	sha512_context ctx;
	sha512_init(&ctx);
	sha512_hash(&ctx, data, len);
	sha512_done(&ctx, hash);
}

void sha384(const void *data, size_t len, uint8_t *hash)
{
	sha512_context ctx;
	uint8_t tmp[64];
	sha384_init(&ctx);
	sha512_hash(&ctx, data, len);
	sha512_done(&ctx, tmp);
	if (hash) memcpy(hash, tmp, 48);
}
