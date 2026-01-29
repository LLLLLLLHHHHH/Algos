#ifndef _DES_H_
#define _DES_H_

#include <stdint.h>
#include <stddef.h>

// DES Block Size is 64 bits (8 bytes)
#define DES_BLOCK_SIZE 8

typedef struct {
    uint64_t subkeys[16]; // 16 round keys, each 48 bits (stored in 64 bits)
    uint64_t iv;          // Initialization Vector (64 bits)
} DES_ctx;

// Initialization
void DES_init(DES_ctx* ctx, const uint8_t* key);
void DES_init_iv(DES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

// Electronic Codebook (ECB)
// len must be a multiple of DES_BLOCK_SIZE
void DES_ECB_encrypt(DES_ctx* ctx, uint8_t* buf, size_t len);
void DES_ECB_decrypt(DES_ctx* ctx, uint8_t* buf, size_t len);

// Cipher Block Chaining (CBC)
// len must be a multiple of DES_BLOCK_SIZE
void DES_CBC_encrypt(DES_ctx* ctx, uint8_t* buf, size_t len);
void DES_CBC_decrypt(DES_ctx* ctx, uint8_t* buf, size_t len);

// Cipher Feedback (CFB)
// Full block feedback (CFB64)
void DES_CFB_encrypt(DES_ctx* ctx, uint8_t* buf, size_t len);
void DES_CFB_decrypt(DES_ctx* ctx, uint8_t* buf, size_t len);

// Output Feedback (OFB)
void DES_OFB_encrypt(DES_ctx* ctx, uint8_t* buf, size_t len);
// OFB decrypt is the same as encrypt
#define DES_OFB_decrypt DES_OFB_encrypt

// Counter (CTR)
void DES_CTR_encrypt(DES_ctx* ctx, uint8_t* buf, size_t len);
// CTR decrypt is the same as encrypt
#define DES_CTR_decrypt DES_CTR_encrypt

#endif // _DES_H_
