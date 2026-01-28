
#ifndef SALSA20_H
#define SALSA20_H

#include <stdint.h>
#include <stddef.h>

typedef struct {
    uint32_t state[16];
} salsa20_context;

/**
 * \brief Initialize Salsa20 context
 *
 * \param ctx   Context to initialize
 * \param key   32-byte (256-bit) key
 * \param nonce 8-byte (64-bit) nonce
 */
void salsa20_init(salsa20_context *ctx, const uint8_t key[32], const uint8_t nonce[8]);

/**
 * \brief Encrypt/Decrypt data using Salsa20
 *
 * \param ctx    Context
 * \param input  Input data
 * \param output Output buffer
 * \param len    Length of data
 */
void salsa20_crypt(salsa20_context *ctx, const uint8_t *input, uint8_t *output, size_t len);

#endif
