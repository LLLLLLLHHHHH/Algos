
#include "salsa20.h"
#include <string.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))

#define QR(a,b,c,d) \
	b ^= ROTL(a + d, 7); \
	c ^= ROTL(b + a, 9); \
	d ^= ROTL(c + b, 13); \
	a ^= ROTL(d + c, 18);

static const char constant[16] = "expand 32-byte k";

static uint32_t load32_le(const uint8_t *src) {
    return ((uint32_t)src[0]) |
           ((uint32_t)src[1] << 8) |
           ((uint32_t)src[2] << 16) |
           ((uint32_t)src[3] << 24);
}

static void store32_le(uint8_t *dst, uint32_t val) {
    dst[0] = (uint8_t)(val);
    dst[1] = (uint8_t)(val >> 8);
    dst[2] = (uint8_t)(val >> 16);
    dst[3] = (uint8_t)(val >> 24);
}

void salsa20_init(salsa20_context *ctx, const uint8_t key[32], const uint8_t nonce[8]) {
    // Constants "expand 32-byte k"
    // sigma = "expand 32-byte k"
    ctx->state[0]  = load32_le((const uint8_t*)constant);
    ctx->state[5]  = load32_le((const uint8_t*)constant + 4);
    ctx->state[10] = load32_le((const uint8_t*)constant + 8);
    ctx->state[15] = load32_le((const uint8_t*)constant + 12);

    // Key
    ctx->state[1] = load32_le(key);
    ctx->state[2] = load32_le(key + 4);
    ctx->state[3] = load32_le(key + 8);
    ctx->state[4] = load32_le(key + 12);
    ctx->state[11] = load32_le(key + 16);
    ctx->state[12] = load32_le(key + 20);
    ctx->state[13] = load32_le(key + 24);
    ctx->state[14] = load32_le(key + 28);

    // Nonce
    ctx->state[6] = load32_le(nonce);
    ctx->state[7] = load32_le(nonce + 4);

    // Block counter (64-bit), starts at 0
    ctx->state[8] = 0;
    ctx->state[9] = 0;
}

static void salsa20_block(uint32_t state[16], uint8_t output[64]) {
    uint32_t x[16];
    int i;

    memcpy(x, state, 64);

    for (i = 0; i < 10; i++) {
        // Column rounds
        QR(x[ 0], x[ 4], x[ 8], x[12]);
        QR(x[ 5], x[ 9], x[13], x[ 1]);
        QR(x[10], x[14], x[ 2], x[ 6]);
        QR(x[15], x[ 3], x[ 7], x[11]);

        // Row rounds
        QR(x[ 0], x[ 1], x[ 2], x[ 3]);
        QR(x[ 5], x[ 6], x[ 7], x[ 4]);
        QR(x[10], x[11], x[ 8], x[ 9]);
        QR(x[15], x[12], x[13], x[14]);
    }

    for (i = 0; i < 16; i++) {
        x[i] += state[i];
        store32_le(output + i * 4, x[i]);
    }
}

void salsa20_crypt(salsa20_context *ctx, const uint8_t *input, uint8_t *output, size_t len) {
    uint8_t block[64];
    size_t i = 0;

    while (len > 0) {
        salsa20_block(ctx->state, block);

        // Increment 64-bit counter (state[8] and state[9])
        ctx->state[8]++;
        if (ctx->state[8] == 0) {
            ctx->state[9]++;
        }

        size_t n = (len < 64) ? len : 64;
        for (size_t j = 0; j < n; j++) {
            output[i + j] = input[i + j] ^ block[j];
        }

        i += n;
        len -= n;
    }
}
