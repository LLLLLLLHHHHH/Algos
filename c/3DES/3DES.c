#include "3DES.h"
#include <string.h>

// ---------------------------------------------------------------------------
// Tables (Standard FIPS 46-3) - Same as DES
// ---------------------------------------------------------------------------

static const uint8_t IP[64] = {
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
};

static const uint8_t IP_INV[64] = {
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
};

static const uint8_t E[48] = {
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
};

static const uint8_t P[32] = {
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
};

static const uint8_t PC1[56] = {
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
};

static const uint8_t PC2[48] = {
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
};

static const uint8_t SHIFTS[16] = {
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

static const uint8_t S_BOX[8][4][16] = {
    // S1
    {
        {14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
        {0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
        {4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
        {15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
    },
    // S2
    {
        {15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
        {3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
        {0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
        {13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
    },
    // S3
    {
        {10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
        {13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
        {13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
        {1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
    },
    // S4
    {
        {7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
        {13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
        {10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
        {3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
    },
    // S5
    {
        {2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
        {14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
        {4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
        {11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
    },
    // S6
    {
        {12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
        {10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
        {9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
        {4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
    },
    // S7
    {
        {4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
        {13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
        {1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
        {6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
    },
    // S8
    {
        {13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
        {1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
        {7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
        {2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
    }
};

// ---------------------------------------------------------------------------
// Helper Functions
// ---------------------------------------------------------------------------

static inline int get_bit(uint64_t val, int pos) {
    return (val >> (64 - pos)) & 1;
}

static uint64_t permute(uint64_t input, const uint8_t* table, int n) {
    uint64_t result = 0;
    for (int i = 0; i < n; i++) {
        if (get_bit(input, table[i])) {
            result |= (1ULL << (64 - 1 - i));
        }
    }
    return result;
}

static uint32_t rotl28(uint32_t val, int shift) {
    return ((val << shift) | (val >> (28 - shift))) & 0x0FFFFFFF;
}

static uint64_t bytes_to_u64(const uint8_t* b) {
    uint64_t res = 0;
    for (int i = 0; i < 8; i++) {
        res = (res << 8) | b[i];
    }
    return res;
}

static void u64_to_bytes(uint64_t val, uint8_t* b) {
    for (int i = 7; i >= 0; i--) {
        b[i] = (uint8_t)(val & 0xFF);
        val >>= 8;
    }
}

// ---------------------------------------------------------------------------
// Core Logic (Single Key Schedule)
// ---------------------------------------------------------------------------

static void des_key_schedule(const uint8_t* key, uint64_t* subkeys) {
    uint64_t k = bytes_to_u64(key);
    
    // PC1: 56 bits
    uint64_t k56 = permute(k, PC1, 56);
    
    uint32_t c = (uint32_t)((k56 >> 36) & 0x0FFFFFFF);
    uint32_t d = (uint32_t)((k56 >> 8) & 0x0FFFFFFF);
    
    for (int i = 0; i < 16; i++) {
        c = rotl28(c, SHIFTS[i]);
        d = rotl28(d, SHIFTS[i]);
        
        uint64_t cd = ((uint64_t)c << 28) | d;
        cd <<= 8; 
        
        subkeys[i] = permute(cd, PC2, 48);
    }
}

// Feistel function F(R, K)
static uint32_t des_f(uint32_t r, uint64_t k) {
    uint64_t r_u64 = (uint64_t)r << 32; 
    uint64_t er = permute(r_u64, E, 48); 
    
    uint64_t x = er ^ k;
    
    uint32_t output = 0;
    for (int i = 0; i < 8; i++) {
        int shift = 64 - 6 * (i + 1);
        uint8_t chunk = (x >> shift) & 0x3F;
        
        int row = ((chunk >> 5) & 1) * 2 + (chunk & 1);
        int col = (chunk >> 1) & 0x0F;
        
        uint32_t s_val = S_BOX[i][row][col];
        output = (output << 4) | s_val;
    }
    
    uint64_t out_u64 = (uint64_t)output << 32;
    uint64_t p_out = permute(out_u64, P, 32);
    
    return (uint32_t)(p_out >> 32);
}

// Single DES Block Operation
// mode: 1 for encrypt, 0 for decrypt
static uint64_t des_block_op(uint64_t block, uint64_t* subkeys, int mode) {
    block = permute(block, IP, 64);
    
    uint32_t l = (uint32_t)(block >> 32);
    uint32_t r = (uint32_t)(block & 0xFFFFFFFF);
    
    for (int i = 0; i < 16; i++) {
        uint32_t prev_l = l;
        l = r;
        
        uint64_t k;
        if (mode == 1) { // Encrypt
            k = subkeys[i];
        } else { // Decrypt
            k = subkeys[15 - i];
        }
        
        r = prev_l ^ des_f(r, k);
    }
    
    uint64_t combined = ((uint64_t)r << 32) | l;
    return permute(combined, IP_INV, 64);
}

// ---------------------------------------------------------------------------
// 3DES Core
// ---------------------------------------------------------------------------

void TDES_init(TDES_ctx* ctx, const uint8_t* key) {
    des_key_schedule(key, ctx->subkeys1);
    des_key_schedule(key + 8, ctx->subkeys2);
    des_key_schedule(key + 16, ctx->subkeys3);
    ctx->iv = 0;
}

void TDES_init_iv(TDES_ctx* ctx, const uint8_t* key, const uint8_t* iv) {
    TDES_init(ctx, key);
    if (iv) {
        ctx->iv = bytes_to_u64(iv);
    }
}

// 3DES EDE Block Operation
// Encrypt: E(K1) -> D(K2) -> E(K3)
// Decrypt: D(K3) -> E(K2) -> D(K1)
static uint64_t tdes_process_block(TDES_ctx* ctx, uint64_t block, int mode) {
    if (mode == 1) { // Encrypt
        block = des_block_op(block, ctx->subkeys1, 1); // Encrypt K1
        block = des_block_op(block, ctx->subkeys2, 0); // Decrypt K2
        block = des_block_op(block, ctx->subkeys3, 1); // Encrypt K3
    } else { // Decrypt
        block = des_block_op(block, ctx->subkeys3, 0); // Decrypt K3
        block = des_block_op(block, ctx->subkeys2, 1); // Encrypt K2
        block = des_block_op(block, ctx->subkeys1, 0); // Decrypt K1
    }
    return block;
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

void TDES_ECB_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = bytes_to_u64(buf + i);
        block = tdes_process_block(ctx, block, 1);
        u64_to_bytes(block, buf + i);
    }
}

void TDES_ECB_decrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = bytes_to_u64(buf + i);
        block = tdes_process_block(ctx, block, 0);
        u64_to_bytes(block, buf + i);
    }
}

void TDES_CBC_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = bytes_to_u64(buf + i);
        block ^= ctx->iv;
        block = tdes_process_block(ctx, block, 1);
        ctx->iv = block;
        u64_to_bytes(block, buf + i);
    }
}

void TDES_CBC_decrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t block = bytes_to_u64(buf + i);
        uint64_t next_iv = block;
        block = tdes_process_block(ctx, block, 0);
        block ^= ctx->iv;
        ctx->iv = next_iv;
        u64_to_bytes(block, buf + i);
    }
}

void TDES_CFB_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t iv_enc = tdes_process_block(ctx, ctx->iv, 1);
        uint64_t block = bytes_to_u64(buf + i);
        block ^= iv_enc;
        ctx->iv = block;
        u64_to_bytes(block, buf + i);
    }
}

void TDES_CFB_decrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t iv_enc = tdes_process_block(ctx, ctx->iv, 1);
        uint64_t block = bytes_to_u64(buf + i);
        uint64_t next_iv = block;
        block ^= iv_enc;
        ctx->iv = next_iv;
        u64_to_bytes(block, buf + i);
    }
}

void TDES_OFB_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t iv_enc = tdes_process_block(ctx, ctx->iv, 1);
        ctx->iv = iv_enc;
        uint64_t block = bytes_to_u64(buf + i);
        block ^= iv_enc;
        u64_to_bytes(block, buf + i);
    }
}

void TDES_CTR_encrypt(TDES_ctx* ctx, uint8_t* buf, size_t len) {
    for (size_t i = 0; i < len; i += 8) {
        uint64_t keystream = tdes_process_block(ctx, ctx->iv, 1);
        ctx->iv++; 
        
        uint64_t block = bytes_to_u64(buf + i);
        block ^= keystream;
        u64_to_bytes(block, buf + i);
    }
}
