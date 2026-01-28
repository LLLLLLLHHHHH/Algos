
#include "SHA1.h"
#include <string.h>

#define rol(value, bits) (((value) << (bits)) | ((value) >> (32 - (bits))))

// Helper to read 32-bit big-endian integer
static uint32_t get_uint32_be(const uint8_t *b, int i)
{
    return ((uint32_t)b[i] << 24) | ((uint32_t)b[i + 1] << 16) |
           ((uint32_t)b[i + 2] << 8) | ((uint32_t)b[i + 3]);
}

// Helper to write 32-bit big-endian integer
static void put_uint32_be(uint32_t n, uint8_t *b, int i)
{
    b[i] = (uint8_t)(n >> 24);
    b[i + 1] = (uint8_t)(n >> 16);
    b[i + 2] = (uint8_t)(n >> 8);
    b[i + 3] = (uint8_t)n;
}

void SHA1Init(SHA1_CTX *context)
{
    context->state[0] = 0x67452301;
    context->state[1] = 0xEFCDAB89;
    context->state[2] = 0x98BADCFE;
    context->state[3] = 0x10325476;
    context->state[4] = 0xC3D2E1F0;
    context->count[0] = context->count[1] = 0;
}

void SHA1Transform(uint32_t state[5], const uint8_t buffer[64])
{
    uint32_t a, b, c, d, e;
    uint32_t w[80];
    int i;

    for (i = 0; i < 16; i++) {
        w[i] = get_uint32_be(buffer, i * 4);
    }
    for (i = 16; i < 80; i++) {
        w[i] = rol(w[i-3] ^ w[i-8] ^ w[i-14] ^ w[i-16], 1);
    }

    a = state[0];
    b = state[1];
    c = state[2];
    d = state[3];
    e = state[4];

    for (i = 0; i < 20; i++) {
        uint32_t temp = rol(a, 5) + ((b & c) | (~b & d)) + e + 0x5A827999 + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    for (i = 20; i < 40; i++) {
        uint32_t temp = rol(a, 5) + (b ^ c ^ d) + e + 0x6ED9EBA1 + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    for (i = 40; i < 60; i++) {
        uint32_t temp = rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    for (i = 60; i < 80; i++) {
        uint32_t temp = rol(a, 5) + (b ^ c ^ d) + e + 0xCA62C1D6 + w[i];
        e = d;
        d = c;
        c = rol(b, 30);
        b = a;
        a = temp;
    }

    state[0] += a;
    state[1] += b;
    state[2] += c;
    state[3] += d;
    state[4] += e;
}

void SHA1Update(SHA1_CTX *context, const uint8_t *data, uint32_t len)
{
    uint32_t i, j;

    j = (context->count[0] >> 3) & 63;
    if ((context->count[0] += len << 3) < (len << 3))
        context->count[1]++;
    context->count[1] += (len >> 29);

    if ((j + len) > 63) {
        memcpy(&context->buffer[j], data, (i = 64 - j));
        SHA1Transform(context->state, context->buffer);
        for (; i + 63 < len; i += 64) {
            SHA1Transform(context->state, &data[i]);
        }
        j = 0;
    }
    else i = 0;
    memcpy(&context->buffer[j], &data[i], len - i);
}

void SHA1Final(uint8_t digest[20], SHA1_CTX *context)
{
    uint32_t i;
    uint8_t finalcount[8];
    
    put_uint32_be(context->count[1], finalcount, 0);
    put_uint32_be(context->count[0], finalcount, 4);

    i = (context->count[0] >> 3) & 63;
    
    context->buffer[i++] = 0x80;
    
    if (i > 56) {
        while (i < 64) {
            context->buffer[i++] = 0;
        }
        SHA1Transform(context->state, context->buffer);
        i = 0;
    }
    
    while (i < 56) {
        context->buffer[i++] = 0;
    }
    
    memcpy(&context->buffer[56], finalcount, 8);
    SHA1Transform(context->state, context->buffer);
    
    for (i = 0; i < 5; i++) {
        put_uint32_be(context->state[i], digest, i * 4);
    }
}

void SHA1(const uint8_t *data, uint32_t len, uint8_t digest[20])
{
    SHA1_CTX ctx;
    SHA1Init(&ctx);
    SHA1Update(&ctx, data, len);
    SHA1Final(digest, &ctx);
}
