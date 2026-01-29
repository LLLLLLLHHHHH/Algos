#ifndef _3DES_H_
#define _3DES_H_

#include <stdint.h>
#include <stddef.h>

// 3DES Block Size is 64 bits (8 bytes)
#define TDES_BLOCK_SIZE 8

// 3DES Key Size: 24 bytes (192 bits) for Option 1 (3 Keys)
// Note: If using Option 2 (2 Keys), the caller should duplicate the first 8 bytes to the end (K1, K2, K1).
#define TDES_KEY_SIZE 24

typedef struct {
    uint64_t subkeys1[16]; // Subkeys for Key 1
    uint64_t subkeys2[16]; // Subkeys for Key 2
    uint64_t subkeys3[16]; // Subkeys for Key 3
    uint64_t iv;           // Initialization Vector
} TDES_ctx;

// Initialization
// key must be 24 bytes
void TDES_init(TDES_ctx* ctx, const uint8_t* key);
void TDES_init_iv(TDES_ctx* ctx, const uint8_t* key, const uint8_t* iv);

// Electronic Codebook (ECB)
void TDES_ECB_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);
void TDES_ECB_decrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);

// Cipher Block Chaining (CBC)
void TDES_CBC_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);
void TDES_CBC_decrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);

// Cipher Feedback (CFB)
void TDES_CFB_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);
void TDES_CFB_decrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);

// Output Feedback (OFB)
void TDES_OFB_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);
#define TDES_OFB_decrypt TDES_OFB_encrypt

// Counter (CTR)
void TDES_CTR_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len);
#define TDES_CTR_decrypt TDES_CTR_encrypt

#endif // _3DES_H_
