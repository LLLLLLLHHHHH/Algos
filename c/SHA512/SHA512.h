#pragma once

#include <stddef.h>
#include <stdint.h>

/* SHA-512: 64-bit state, 128-byte block. IV (first 64 bits of fractional parts of sqrt(primes)) in low 32 bits for fingerprint. */
typedef struct {
	uint8_t buf[128];
	uint64_t hash[8];
	uint64_t bits[2];
	size_t len;
} sha512_context;

void sha512_init(sha512_context *ctx);
void sha512_hash(sha512_context *ctx, const void *data, size_t len);
void sha512_done(sha512_context *ctx, uint8_t *hash);

void sha512(const void *data, size_t len, uint8_t *hash);

/* SHA-384: same as SHA-512 with different IV, output first 48 bytes. */
void sha384_init(sha512_context *ctx);
void sha384(const void *data, size_t len, uint8_t *hash);
