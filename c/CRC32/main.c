#include <stdio.h>
#include <string.h>
#include "crc32.h"

int main() {
    // Test Vector 1: "123456789"
    // Expected CRC32: 0xCBF43926
    const char *data1 = "123456789";
    uint32_t result1 = crc32_total((const uint8_t*)data1, strlen(data1));
    printf("Test 1: '%s'\n", data1);
    printf("Expected: 0xCBF43926\n");
    printf("Result:   0x%08X\n", result1);
    if (result1 == 0xCBF43926) {
        printf("PASS\n\n");
    } else {
        printf("FAIL\n\n");
    }

    // Test Vector 2: "The quick brown fox jumps over the lazy dog"
    // Expected CRC32: 0x414FA339
    const char *data2 = "The quick brown fox jumps over the lazy dog";
    uint32_t result2 = crc32_total((const uint8_t*)data2, strlen(data2));
    printf("Test 2: '%s'\n", data2);
    printf("Expected: 0x414FA339\n");
    printf("Result:   0x%08X\n", result2);
    if (result2 == 0x414FA339) {
        printf("PASS\n\n");
    } else {
        printf("FAIL\n\n");
    }

    // Test 3: Segmented calculation
    // "123456789" split into "12345" and "6789"
    const char *part1 = "12345";
    const char *part2 = "6789";
    uint32_t crc = 0xFFFFFFFF;
    crc = crc32(crc, (const uint8_t*)part1, strlen(part1));
    crc = crc32(crc, (const uint8_t*)part2, strlen(part2));
    uint32_t result3 = crc ^ 0xFFFFFFFF;
    
    printf("Test 3: Segmented calculation ('12345' + '6789')\n");
    printf("Expected: 0xCBF43926\n");
    printf("Result:   0x%08X\n", result3);
    if (result3 == 0xCBF43926) {
        printf("PASS\n\n");
    } else {
        printf("FAIL\n\n");
    }

    return 0;
}
