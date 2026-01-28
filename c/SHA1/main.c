
#include <stdio.h>
#include <string.h>
#include "SHA1.h"

int main()
{
    uint8_t digest[20];
    const char *data = "abc";
    
    printf("Message: %s\n", data);
    
    SHA1((const uint8_t*)data, strlen(data), digest);
    
    printf("SHA1: ");
    for (int i = 0; i < 20; i++) {
        printf("%02x", digest[i]);
    }
    printf("\n");
    
    const char *expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
    printf("Expect: %s\n", expected);
    
    return 0;
}
