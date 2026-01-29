#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "DES.h"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static void test_ecb() {
    printf("Testing ECB...\n");
    uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t plain[16] = "Now is the time "; // 16 bytes
    uint8_t buf[16];
    uint8_t decrypted[16];

    DES_ctx ctx;
    DES_init(&ctx, key);

    memcpy(buf, plain, 16);
    DES_ECB_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    DES_ECB_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("ECB Test Passed\n");
    } else {
        printf("ECB Test FAILED\n");
    }
    printf("\n");
}

static void test_cbc() {
    printf("Testing CBC...\n");
    uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t iv[8]  = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    uint8_t plain[16] = "Basic CBC Test!!";
    uint8_t buf[16];
    
    DES_ctx ctx;
    
    // Encrypt
    DES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    DES_CBC_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    // Re-init IV for decryption
    DES_init_iv(&ctx, key, iv);
    DES_CBC_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("CBC Test Passed\n");
    } else {
        printf("CBC Test FAILED\n");
    }
    printf("\n");
}

static void test_ctr() {
    printf("Testing CTR...\n");
    uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t iv[8]  = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7};
    uint8_t plain[16] = "Counter Mode Tst";
    uint8_t buf[16];
    
    DES_ctx ctx;
    
    // Encrypt
    DES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    DES_CTR_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    DES_init_iv(&ctx, key, iv);
    DES_CTR_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("CTR Test Passed\n");
    } else {
        printf("CTR Test FAILED\n");
    }
    printf("\n");
}

static void test_cfb() {
    printf("Testing CFB...\n");
    uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t iv[8]  = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t plain[16] = "CFB Mode Test!!!";
    uint8_t buf[16];
    
    DES_ctx ctx;
    
    // Encrypt
    DES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    DES_CFB_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    DES_init_iv(&ctx, key, iv);
    DES_CFB_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("CFB Test Passed\n");
    } else {
        printf("CFB Test FAILED\n");
    }
    printf("\n");
}

static void test_ofb() {
    printf("Testing OFB...\n");
    uint8_t key[8] = {0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF};
    uint8_t iv[8]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t plain[16] = "OFB Mode Test!!!";
    uint8_t buf[16];
    
    DES_ctx ctx;
    
    // Encrypt
    DES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    DES_OFB_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    DES_init_iv(&ctx, key, iv);
    DES_OFB_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("OFB Test Passed\n");
    } else {
        printf("OFB Test FAILED\n");
    }
    printf("\n");
}

int main() {
    test_ecb();
    test_cbc();
    test_ctr();
    test_cfb();
    test_ofb();
    return 0;
}
