#pragma once

#include <stddef.h>
#include <stdint.h>

/* SHA3-256 (FIPS 202): output 32 bytes. Keccak constants for fingerprint: 0x01, 0x82, 0x80000000, etc. */
void sha3_256(const void *data, size_t len, uint8_t *hash);

/* SHA3-512: output 64 bytes. */
void sha3_512(const void *data, size_t len, uint8_t *hash);
