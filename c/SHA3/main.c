#include <stdio.h>
#include <string.h>
#include "SHA3.h"

int main(void)
{
	uint8_t *input = (uint8_t *)"123456";
	uint8_t out256[32], out512[64];
	int i;

	sha3_256(input, strlen((char*)input), out256);
	printf("SHA3-256: ");
	for (i = 0; i < 32; i++) printf("%02x", out256[i]);
	printf("\n");

	sha3_512(input, strlen((char*)input), out512);
	printf("SHA3-512: ");
	for (i = 0; i < 64; i++) printf("%02x", out512[i]);
	printf("\n");
	return 0;
}
