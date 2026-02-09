#include <stdio.h>
#include <string.h>
#include "SHA512.h"

int main(void)
{
	uint8_t *input = (uint8_t *)"123456";
	uint8_t out512[64], out384[48];

	sha512(input, strlen((char*)input), out512);
	printf("SHA-512: ");
	for (int i = 0; i < 64; i++) printf("%02x", out512[i]);
	printf("\n");

	sha384(input, strlen((char*)input), out384);
	printf("SHA-384: ");
	for (int i = 0; i < 48; i++) printf("%02x", out384[i]);
	printf("\n");
	return 0;
}
