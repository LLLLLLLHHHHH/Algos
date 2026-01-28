
#include "chacha20.h"
#include <string.h>

#define ROTL(a,b) (((a) << (b)) | ((a) >> (32 - (b))))
#define QR(a, b, c, d) \
    a += b; d ^= a; d = ROTL(d, 16); \
    c += d; b ^= c; b = ROTL(b, 12); \
    a += b; d ^= a; d = ROTL(d, 8); \
    c += d; b ^= c; b = ROTL(b, 7);

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

void chacha20_init(chacha20_context *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    // Constants
    ctx->state[0] = load32_le((const uint8_t*)constant);
    ctx->state[1] = load32_le((const uint8_t*)constant + 4);
    ctx->state[2] = load32_le((const uint8_t*)constant + 8);
    ctx->state[3] = load32_le((const uint8_t*)constant + 12);

    // Key
    for (int i = 0; i < 8; i++) {
        ctx->state[4 + i] = load32_le(key + i * 4);
    }

    // Counter
    ctx->state[12] = counter;

    // Nonce
    for (int i = 0; i < 3; i++) {
        ctx->state[13 + i] = load32_le(nonce + i * 4);
    }
}

static void chacha20_block(chacha20_context *ctx, uint8_t output[64]) {
    uint32_t x[16];
    memcpy(x, ctx->state, 64);

    for (int i = 0; i < 10; i++) {
        // Column rounds
        QR(x[0], x[4], x[8],  x[12]);
        QR(x[1], x[5], x[9],  x[13]);
        QR(x[2], x[6], x[10], x[14]);
        QR(x[3], x[7], x[11], x[15]);
        
        // Diagonal rounds
        QR(x[0], x[5], x[10], x[15]);
        QR(x[1], x[6], x[11], x[12]);
        QR(x[2], x[7], x[8],  x[13]);
        QR(x[3], x[4], x[9],  x[14]);
    }

    for (int i = 0; i < 16; i++) {
        x[i] += ctx->state[i];
        store32_le(output + i * 4, x[i]);
    }
}

void chacha20_crypt(chacha20_context *ctx, const uint8_t *input, uint8_t *output, size_t len) {
    uint8_t block[64];
    size_t i = 0;

    while (len > 0) {
        chacha20_block(ctx, block);
        
        // Increment counter
        ctx->state[12]++;
        // Note: We don't handle 64-bit counter overflow for state[12] here as per standard 96-bit nonce usage,
        // it just wraps around 32-bit. RFC 7539 uses 32-bit counter.

        size_t n = (len < 64) ? len : 64;
        for (size_t j = 0; j < n; j++) {
            output[i + j] = input[i + j] ^ block[j];
        }

        i += n;
        len -= n;
    }
}
