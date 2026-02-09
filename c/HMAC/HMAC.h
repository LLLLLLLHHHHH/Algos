#pragma once

#include <stddef.h>
#include <stdint.h>

/** HMAC-SHA256: key and message arbitrary bytes, output 32 bytes. */
void hmac_sha256(const void *key, size_t key_len, const void *msg, size_t msg_len, uint8_t *out);
