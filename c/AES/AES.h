#pragma once

#include <stdint.h>
#include <stddef.h>

#define AES128 1
// #define AES192 1
// #define AES256 1

// 无论使用哪种 AES 变体（AES-128、AES-192 或 AES-256），数据块的大小始终为 128 位，即 16 字节，4 x 4 矩阵
#define AES_BLOCKLEN 16

// AES_KEYLEN 密钥长度，单位是字节
// AES_keyExpSize 存储扩展密钥的数组大小，单位为字节。AES_keyExpSize = (Nr + 1) × AES_KEYLEN
#if defined(AES256) && (AES256 == 1)
    #define AES_KEYLEN 32
    #define AES_keyExpSize 240
#elif defined(AES192) && (AES192 == 1)
    #define AES_KEYLEN 24
    #define AES_keyExpSize 208
#else
    #define AES_KEYLEN 16 
    #define AES_keyExpSize 176
#endif

typedef struct _AES_ctx
{
    uint8_t RoundKey[AES_keyExpSize];
    uint8_t Iv[AES_BLOCKLEN];
} AES_ctx;

void AES_init_ctx(AES_ctx* ctx, const uint8_t* key);
void AES_init_ctx_iv(AES_ctx* ctx, const uint8_t* key, const uint8_t* iv);
void AES_ctx_set_iv(AES_ctx* ctx, const uint8_t* iv);

// 缓冲区大小恰好为 AES_BLOCKLEN 字节；
// 在 ECB 模式下，仅需使用 AES_init_ctx，因为 ECB 不使用初始化向量（IV）。
// 注意：ECB 模式被认为是不安全的。
void AES_ECB_encrypt_buffer(const AES_ctx* ctx, uint8_t* buf);
void AES_ECB_decrypt_buffer(const AES_ctx* ctx, uint8_t* buf);

// 缓冲区大小必须是 AES_BLOCKLEN 的倍数；
// 建议使用 PKCS#7 填充方案进行填充
// 注意：
//   - 您需要通过 AES_init_ctx_iv() 或 AES_ctx_set_iv() 在上下文中设置 IV。
//   - 永远不要使用相同的密钥重复使用 IV。
void AES_CBC_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CBC_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);

// 加密和解密使用相同的函数。
// 对于每个数据块，IV（初始化向量）都会递增，并在加密后用作输出的 XOR 补码。
// 建议使用 PKCS#7 填充方案。
// 注意：
//   - 您需要通过 AES_init_ctx_iv() 或 AES_ctx_set_iv() 在上下文中设置 IV。
//   - 永远不要使用相同的密钥重复使用 IV。
void AES_CTR_xcrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);

// CFB (Cipher Feedback Mode)
// 缓冲区大小必须是 AES_BLOCKLEN 的倍数
void AES_CFB_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);
void AES_CFB_decrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);

// OFB (Output Feedback Mode)
// 缓冲区大小必须是 AES_BLOCKLEN 的倍数
void AES_OFB_encrypt_buffer(AES_ctx* ctx, uint8_t* buf, size_t length);
// OFB 解密与加密相同
#define AES_OFB_decrypt_buffer AES_OFB_encrypt_buffer

// GCM (Galois/Counter Mode)
// GCM 是一种认证加密模式，提供保密性和完整性。
// iv: 初始化向量 (推荐 12 字节)
// iv_len: iv 长度
// aad: 附加认证数据 (Additional Authenticated Data)，可以为 NULL
// aad_len: aad 长度
// input: 输入数据
// output: 输出数据 (长度与 input 相同)
// length: 数据长度
// tag: 认证标签输出 (加密时) 或 输入 (解密时)
// tag_len: 标签长度 (通常 16 字节)
// 返回值: 解密成功返回 0，认证失败返回 1 (仅解密时有效)
void AES_GCM_encrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len);

int AES_GCM_decrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     const uint8_t* tag, size_t tag_len);

// CCM (Counter with CBC-MAC)
// CCM 是一种认证加密模式，提供保密性和完整性。
// iv: Nonce (长度 7 到 13 字节)
// iv_len: Nonce 长度
// aad: 附加认证数据 (Additional Authenticated Data)
// aad_len: aad 长度
// input: 输入数据
// output: 输出数据 (长度与 input 相同)
// length: 数据长度
// tag: 认证标签输出 (加密时) 或 输入 (解密时)
// tag_len: 标签长度 (通常为 4, 6, 8, 10, 12, 14, 16 字节)
// 返回值: 解密成功返回 0，认证失败返回 1 (仅解密时有效)
void AES_CCM_encrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len);

int AES_CCM_decrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     const uint8_t* tag, size_t tag_len);

// EAX Mode
// EAX 是一种认证加密模式，提供保密性和完整性。
// iv: Nonce (任意长度)
// iv_len: Nonce 长度
// header: 附加认证数据 (AAD)
// header_len: AAD 长度
// input: 输入数据
// output: 输出数据 (长度与 input 相同)
// length: 数据长度
// tag: 认证标签输出 (加密时) 或 输入 (解密时)
// tag_len: 标签长度 (通常 16 字节)
void AES_EAX_encrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* header, size_t header_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len);

int AES_EAX_decrypt(AES_ctx* ctx, 
                     const uint8_t* iv, size_t iv_len,
                     const uint8_t* header, size_t header_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     const uint8_t* tag, size_t tag_len);

// OCB (Offset Codebook Mode, RFC 7253 / OCB3)
// OCB 是一种认证加密模式（AEAD），提供保密性与完整性。
// nonce: 需要保证在同一 key 下**绝不重复**（建议用计数器），长度 1..15 字节
// nonce_len: nonce 长度（字节）
// aad: 附加认证数据 (Additional Authenticated Data)，可以为 NULL
// aad_len: aad 长度（字节）
// input: 输入数据（明文/密文核心）
// output: 输出数据（密文核心/明文），长度与 input 相同
// length: 数据长度（字节）
// tag: 认证标签输出 (加密时) 或 输入 (解密时)
// tag_len: 标签长度（字节，1..16；常用 16）
// 返回值: 解密成功返回 0，认证失败返回 1（仅解密时有效）
void AES_OCB_encrypt(AES_ctx* ctx,
                     const uint8_t* nonce, size_t nonce_len,
                     const uint8_t* aad, size_t aad_len,
                     const uint8_t* input, uint8_t* output, size_t length,
                     uint8_t* tag, size_t tag_len);

int AES_OCB_decrypt(AES_ctx* ctx,
                    const uint8_t* nonce, size_t nonce_len,
                    const uint8_t* aad, size_t aad_len,
                    const uint8_t* input, uint8_t* output, size_t length,
                    const uint8_t* tag, size_t tag_len);



