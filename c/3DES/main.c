#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include "3DES.h"

static void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02X", data[i]);
    }
    printf("\n");
}

static void test_ecb() {
    printf("Testing 3DES ECB...\n");
    // 3 Key Option: K1, K2, K3
    uint8_t key[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, // K2
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23  // K3
    };
    uint8_t plain[16] = "ThreeKeyTripleD!";
    uint8_t buf[16];

    TDES_ctx ctx;
    TDES_init(&ctx, key);

    memcpy(buf, plain, 16);
    TDES_ECB_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    TDES_ECB_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("ECB Test Passed\n");
    } else {
        printf("ECB Test FAILED\n");
    }
    printf("\n");
}

static void test_cbc() {
    printf("Testing 3DES CBC...\n");
    uint8_t key[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF // K3 = K1 (Option 2 simulation)
    };
    uint8_t iv[8]  = {0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF};
    uint8_t plain[16] = "3DES CBC Test!!!";
    uint8_t buf[16];
    
    TDES_ctx ctx;
    
    // Encrypt
    TDES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    TDES_CBC_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    TDES_init_iv(&ctx, key, iv);
    TDES_CBC_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("CBC Test Passed\n");
    } else {
        printf("CBC Test FAILED\n");
    }
    printf("\n");
}

static void test_ctr() {
    printf("Testing 3DES CTR...\n");
    uint8_t key[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    };
    uint8_t iv[8]  = {0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7};
    uint8_t plain[16] = "Counter Mode 3DE"; // 16 bytes
    uint8_t buf[16];
    
    TDES_ctx ctx;
    
    // Encrypt
    TDES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    TDES_CTR_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    TDES_init_iv(&ctx, key, iv);
    TDES_CTR_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("CTR Test Passed\n");
    } else {
        printf("CTR Test FAILED\n");
    }
    printf("\n");
}

static void test_cfb() {
    printf("Testing 3DES CFB...\n");
    uint8_t key[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    };
    uint8_t iv[8]  = {0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10};
    uint8_t plain[16] = "CFB Mode Test 3D";
    uint8_t buf[16];
    
    TDES_ctx ctx;
    
    // Encrypt
    TDES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    TDES_CFB_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    TDES_init_iv(&ctx, key, iv);
    TDES_CFB_decrypt(&ctx, buf, 16);
    print_hex("Decrypted", buf, 16);

    if (memcmp(plain, buf, 16) == 0) {
        printf("CFB Test Passed\n");
    } else {
        printf("CFB Test FAILED\n");
    }
    printf("\n");
}

static void test_ofb() {
    printf("Testing 3DES OFB...\n");
    uint8_t key[24] = {
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    };
    uint8_t iv[8]  = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    uint8_t plain[16] = "OFB Mode Test 3D";
    uint8_t buf[16];
    
    TDES_ctx ctx;
    
    // Encrypt
    TDES_init_iv(&ctx, key, iv);
    memcpy(buf, plain, 16);
    TDES_OFB_encrypt(&ctx, buf, 16);
    print_hex("Cipher", buf, 16);

    // Decrypt
    TDES_init_iv(&ctx, key, iv);
    TDES_OFB_decrypt(&ctx, buf, 16);
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
