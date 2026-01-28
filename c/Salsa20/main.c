
#include <stdio.h>
#include <string.h>
#include "salsa20.h"

void print_hex(const char *label, const uint8_t *data, size_t len) {
    printf("%s: ", label);
    for (size_t i = 0; i < len; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

int main() {
    // Test Vector from standard
    // Key: 32 bytes (1 to 32)
    uint8_t key[32];
    for(int i=0; i<32; i++) key[i] = i+1;

    // Nonce: 8 bytes (3 to 10)
    uint8_t nonce[8] = {3, 4, 5, 6, 7, 8, 9, 10};
    
    // Plaintext: "Hello World!"
    const char *plaintext = "Hello World!";
    size_t len = strlen(plaintext);
    uint8_t ciphertext[64];
    uint8_t decrypted[64];

    salsa20_context ctx;

    printf("Plaintext: %s\n", plaintext);

    // Encrypt
    salsa20_init(&ctx, key, nonce);
    salsa20_crypt(&ctx, (const uint8_t*)plaintext, ciphertext, len);
    
    print_hex("Ciphertext", ciphertext, len);

    // Decrypt (Salsa20 is symmetric, so just init and crypt again)
    salsa20_init(&ctx, key, nonce);
    salsa20_crypt(&ctx, ciphertext, decrypted, len);
    decrypted[len] = '\0';

    printf("Decrypted: %s\n", decrypted);

    if (strcmp(plaintext, (char*)decrypted) == 0) {
        printf("Verification Passed!\n");
    } else {
        printf("Verification Failed!\n");
    }

    return 0;
}
