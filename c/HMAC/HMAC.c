#include "HMAC.h"
#include "../SHA256/SHA256.h"

#define IPAD 0x36
#define OPAD 0x5c
#define BLOCK 64
#define HASH_LEN 32

void hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len, uint8_t *out)
{
	uint8_t k0[BLOCK];
	uint8_t ik[BLOCK], ok[BLOCK];
	sha256_context ctx;
	uint8_t inner_hash[HASH_LEN];
	const uint8_t *key_bytes = (const uint8_t *)key;
	const uint8_t *msg_bytes = (const uint8_t *)msg;
	size_t i;

	if (out == NULL) return;

	for (i = 0; i < BLOCK; i++) k0[i] = 0;
	if (key_len <= BLOCK) {
		for (i = 0; i < key_len; i++) k0[i] = key_bytes[i];
	} else {
		sha256(key, key_len, k0);
		for (i = HASH_LEN; i < BLOCK; i++) k0[i] = 0;
	}

	for (i = 0; i < BLOCK; i++) {
		ik[i] = k0[i] ^ IPAD;
		ok[i] = k0[i] ^ OPAD;
	}

	sha256_init(&ctx);
	sha256_hash(&ctx, ik, BLOCK);
	sha256_hash(&ctx, msg_bytes, msg_len);
	sha256_done(&ctx, inner_hash);

	sha256_init(&ctx);
	sha256_hash(&ctx, ok, BLOCK);
	sha256_hash(&ctx, inner_hash, HASH_LEN);
	sha256_done(&ctx, out);
}
