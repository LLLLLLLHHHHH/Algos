
#ifndef CHACHA20_H
#define CHACHA20_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[16];
} chacha20_context;

/**
 * \brief Initialize ChaCha20 context
 *
 * \param ctx   Context to initialize
 * \param key   32-byte key
 * \param nonce 12-byte nonce
 * \param counter Initial counter value (usually 0)
 */
void chacha20_init(chacha20_context *ctx, const uint8_t key[32], const uint8_t nonce[12], uint32_t counter);

/**
 * \brief HChaCha20: derive a 32-byte subkey from key and 16-byte nonce
 *
 * Used by XChaCha20 to support 24-byte (192-bit) nonces.
 *
 * \param key   32-byte key
 * \param nonce 16-byte nonce (first 16 bytes of XChaCha20 nonce)
 * \param out_subkey 32-byte derived subkey
 */
void hchacha20(const uint8_t key[32], const uint8_t nonce[16], uint8_t out_subkey[32]);

/**
 * \brief Initialize XChaCha20 context (192-bit / 24-byte nonce)
 *
 * XChaCha20 uses HChaCha20(key, nonce[0..15]) to derive a subkey,
 * then uses ChaCha20(subkey, counter, 0x00000000||nonce[16..23]).
 *
 * \param ctx   Context to initialize
 * \param key   32-byte key
 * \param nonce 24-byte nonce (192-bit)
 * \param counter Initial counter value (usually 1 per the draft vectors)
 */
void xchacha20_init(chacha20_context *ctx, const uint8_t key[32], const uint8_t nonce[24], uint32_t counter);

/**
 * \brief Encrypt/Decrypt data using ChaCha20 (Symmetric)
 *
 * \param ctx    Context
 * \param input  Input data
 * \param output Output buffer (can be same as input)
 * \param len    Length of data
 */
void chacha20_crypt(chacha20_context *ctx, const uint8_t *input, uint8_t *output, size_t len);

#endif
