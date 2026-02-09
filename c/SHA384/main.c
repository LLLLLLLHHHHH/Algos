#include <stdio.h>
#include <string.h>
#include "../SHA512/SHA512.h"

int main(void)
{
	uint8_t *input = (uint8_t *)"123456";
	uint8_t out[48];
	int i;

	sha384(input, strlen((char*)input), out);
	printf("SHA-384: ");
	for (i = 0; i < 48; i++) printf("%02x", out[i]);
	printf("\n");
	return 0;
}
