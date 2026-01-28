
#include <stdio.h>
#include <string.h>
#include "chacha20.h"

int main() {
    // RFC 7539 Test Vector
    // Key
    uint8_t key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    
    // Nonce (12 bytes)
    uint8_t nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    };
    
    // Counter
    uint32_t counter = 1;

    // Plaintext "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it."
    const char *plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    size_t len = strlen(plaintext);
    uint8_t ciphertext[128];
    uint8_t decrypted[128];

    // Expected ciphertext from RFC 7539 (first block mostly relevant)
    // Actually let's use the exact output check.
    
    printf("Plaintext: %s\n", plaintext);

    chacha20_context ctx;
    
    // Encrypt
    chacha20_init(&ctx, key, nonce, counter);
    chacha20_crypt(&ctx, (const uint8_t*)plaintext, ciphertext, len);
    
    printf("Ciphertext: ");
    for(size_t i = 0; i < len; i++) {
        printf("%02x", ciphertext[i]);
    }
    printf("\n");

    // Decrypt
    chacha20_init(&ctx, key, nonce, counter);
    chacha20_crypt(&ctx, ciphertext, decrypted, len);
    decrypted[len] = '\0';
    
    printf("Decrypted: %s\n", decrypted);

    // Verify against known start of ciphertext
    // Expected first few bytes: 6e 2e 35 9a 25 68 f9 80 41 ba 07 28 dd 0d 69 81
    uint8_t expected_start[] = {0x6e, 0x2e, 0x35, 0x9a, 0x25, 0x68, 0xf9, 0x80, 0x41, 0xba, 0x07, 0x28, 0xdd, 0x0d, 0x69, 0x81};
    if (memcmp(ciphertext, expected_start, sizeof(expected_start)) == 0) {
        printf("Verification Passed!\n");
    } else {
        printf("Verification Failed!\n");
    }

    return 0;
}
