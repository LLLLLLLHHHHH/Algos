
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
 * \brief Encrypt/Decrypt data using ChaCha20 (Symmetric)
 *
 * \param ctx    Context
 * \param input  Input data
 * \param output Output buffer (can be same as input)
 * \param len    Length of data
 */
void chacha20_crypt(chacha20_context *ctx, const uint8_t *input, uint8_t *output, size_t len);

#endif
