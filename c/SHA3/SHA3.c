/*
 * SHA3-256 / SHA3-512 (FIPS 202): 完整 Keccak-f[1600] 与海绵实现，无外部库。
 * 指纹 u32: 0x00000001, 0x00008082, 0x80000000 等 Keccak 轮常数。
 */
#include "SHA3.h"
#include <string.h>

#if defined(_MSC_VER) && _MSC_VER < 1920
typedef unsigned long long uint64_t;
#endif

#define LANES 25
#define ROUNDS 24

/* Keccak-f[1600] 状态: 5x5 个 64 位 lane，按 lane 序存在 state[0..24] */
typedef struct {
	uint64_t state[LANES];
	uint8_t buf[168]; /* max rate/8 = 136 for SHA3-256 */
	size_t buflen;
	size_t rate_bytes; /* 136 for SHA3-256, 72 for SHA3-512 */
} sha3_ctx;

/* FIPS 202 表 3: 轮常数 RC[i] (64-bit) */
static const uint64_t RC[ROUNDS] = {
	0x0000000000000001ULL, 0x0000000000008082ULL, 0x800000000000808aULL,
	0x8000000080008000ULL, 0x000000000000808bULL, 0x0000000080000001ULL,
	0x8000000080008081ULL, 0x8000000000008009ULL, 0x000000000000008aULL,
	0x0000000000000088ULL, 0x0000000080008009ULL, 0x000000008000000aULL,
	0x000000008000808bULL, 0x800000000000008bULL, 0x8000000000008089ULL,
	0x8000000000008003ULL, 0x8000000000008002ULL, 0x8000000000000080ULL,
	0x000000000000800aULL, 0x800000008000000aULL, 0x8000000080008081ULL,
	0x8000000000008080ULL, 0x0000000080000001ULL, 0x8000000080008008ULL
};

/* FIPS 202 表 2: ρ 步旋转偏移 r[x][y] (lane 索引 x+y*5) */
static const uint8_t RHO[LANES] = {
	0, 1, 62, 28, 27, 36, 44, 6, 55, 20, 3, 10, 43, 25, 39, 41, 45, 15, 21, 8, 18, 2, 61, 56, 14
};

/* π 步置换: 新 [x][y] = 旧 [y][2x+3y]，已内联到 B 的索引中 */

static inline uint64_t rotl64(uint64_t x, int n)
{
	n &= 63;
	return (x << n) | (x >> (64 - n));
}

/* 将 state 视为 5x5 lanes，索引 i = x + 5*y */
static uint64_t *lane(sha3_ctx *ctx, int x, int y) { return &ctx->state[x + 5 * y]; }

static void keccak_f1600(sha3_ctx *ctx)
{
	uint64_t C[5], D[5], B[LANES];
	int r, x, y;

	for (r = 0; r < ROUNDS; r++) {
		/* θ: C[x]=A[x,0]^A[x,1]^A[x,2]^A[x,3]^A[x,4], D[x]=C[x-1]^rotl(C[x+1],1) */
		for (x = 0; x < 5; x++) {
			C[x] = *lane(ctx, x, 0) ^ *lane(ctx, x, 1) ^ *lane(ctx, x, 2)
			     ^ *lane(ctx, x, 3) ^ *lane(ctx, x, 4);
		}
		for (x = 0; x < 5; x++) {
			D[x] = C[(x + 4) % 5] ^ rotl64(C[(x + 1) % 5], 1);
		}
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				*lane(ctx, x, y) ^= D[x];

		/* ρ 和 π: new[y][(2x+3y)%5] = rotl(old[x][y], r[x,y])，即 B[y][(2x+3y)%5] */
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++) {
				int ny = (2 * x + 3 * y) % 5;
				B[y + 5 * ny] = rotl64(*lane(ctx, x, y), RHO[x + 5 * y]);
			}

		/* χ: A[x][y] = B[x][y] ^ ((~B[x+1][y]) & B[x+2][y]) */
		for (x = 0; x < 5; x++)
			for (y = 0; y < 5; y++)
				*lane(ctx, x, y) = B[x + 5 * y] ^ ((~B[(x + 1) % 5 + 5 * y]) & B[(x + 2) % 5 + 5 * y]);

		/* ι: A[0][0] ^= RC[r] */
		ctx->state[0] ^= RC[r];
	}
}

/* 将 rate_bytes 字节从 buf 异或进 state（按 little-endian 8 字节 lane） */
static void absorb_block(sha3_ctx *ctx)
{
	size_t i, n = ctx->rate_bytes;
	uint8_t *p = ctx->buf;
	for (i = 0; i < n; i += 8) {
		uint64_t w;
		w = (uint64_t)p[i] | ((uint64_t)p[i+1]<<8) | ((uint64_t)p[i+2]<<16) | ((uint64_t)p[i+3]<<24)
		  | ((uint64_t)p[i+4]<<32) | ((uint64_t)p[i+5]<<40) | ((uint64_t)p[i+6]<<48) | ((uint64_t)p[i+7]<<56);
		ctx->state[i/8] ^= w;
	}
	keccak_f1600(ctx);
}

/* SHA3 填充: M || 0x06 || 0x00... || 0x80，总长为 rate_bytes 的整数倍 */
static void sha3_absorb_final(sha3_ctx *ctx, const uint8_t *in, size_t len)
{
	size_t i, n = ctx->rate_bytes;
	/* 先处理已有缓冲 */
	if (ctx->buflen > 0) {
		size_t take = n - ctx->buflen;
		if (take > len) take = len;
		memcpy(ctx->buf + ctx->buflen, in, take);
		ctx->buflen += take;
		in += take;
		len -= take;
		if (ctx->buflen == n) {
			absorb_block(ctx);
			ctx->buflen = 0;
		}
	}
	/* 整块吸收 */
	while (len >= n) {
		memcpy(ctx->buf, in, n);
		in += n;
		len -= n;
		absorb_block(ctx);
	}
	/* 剩余进入缓冲 */
	memcpy(ctx->buf, in, len);
	ctx->buflen = len;
}

static void sha3_pad_and_final(sha3_ctx *ctx)
{
	size_t n = ctx->rate_bytes;
	/* SHA3 填充: 0x06 然后 0x00... 然后 0x80，使总字节数 = 0 mod n */
	ctx->buf[ctx->buflen++] = 0x06;
	while (ctx->buflen < n)
		ctx->buf[ctx->buflen++] = 0x00;
	ctx->buf[n - 1] |= 0x80;
	absorb_block(ctx);
	ctx->buflen = 0;
}

static void sha3_squeeze(sha3_ctx *ctx, uint8_t *out, size_t outbytes)
{
	size_t n = ctx->rate_bytes;
	size_t done = 0;
	while (done < outbytes) {
		size_t i, tocopy = outbytes - done;
		if (tocopy > n) tocopy = n;
		for (i = 0; i < tocopy; i += 8) {
			uint64_t w = ctx->state[i/8];
			out[done+i  ] = (uint8_t)(w);       out[done+i+1] = (uint8_t)(w>>8);
			out[done+i+2] = (uint8_t)(w>>16);   out[done+i+3] = (uint8_t)(w>>24);
			out[done+i+4] = (uint8_t)(w>>32);   out[done+i+5] = (uint8_t)(w>>40);
			out[done+i+6] = (uint8_t)(w>>48);   out[done+i+7] = (uint8_t)(w>>56);
		}
		done += tocopy;
		if (done < outbytes)
			keccak_f1600(ctx);
	}
}

static void sha3_init(sha3_ctx *ctx, size_t rate_bytes)
{
	memset(ctx->state, 0, sizeof(ctx->state));
	ctx->buflen = 0;
	ctx->rate_bytes = rate_bytes;
}

static void sha3_update(sha3_ctx *ctx, const void *data, size_t len)
{
	sha3_absorb_final(ctx, (const uint8_t *)data, len);
}

static void sha3_final(sha3_ctx *ctx, uint8_t *out, size_t outbytes)
{
	sha3_pad_and_final(ctx);
	sha3_squeeze(ctx, out, outbytes);
}

/* SHA3-256: rate = 1088 bits = 136 bytes, output 32 bytes */
void sha3_256(const void *data, size_t len, uint8_t *hash)
{
	sha3_ctx ctx;
	sha3_init(&ctx, 136);
	sha3_update(&ctx, data, len);
	sha3_final(&ctx, hash, 32);
}

/* SHA3-512: rate = 576 bits = 72 bytes, output 64 bytes */
void sha3_512(const void *data, size_t len, uint8_t *hash)
{
	sha3_ctx ctx;
	sha3_init(&ctx, 72);
	sha3_update(&ctx, data, len);
	sha3_final(&ctx, hash, 64);
}
