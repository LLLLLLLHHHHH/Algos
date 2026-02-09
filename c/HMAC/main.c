#include <stdio.h>
#include <string.h>
#include "HMAC.h"

int main(void)
{
	const char *key = "key";
	const char *msg = "hello";
	uint8_t out[32];
	size_t i;

	hmac_sha256(key, strlen(key), msg, strlen(msg), out);
	for (i = 0; i < 32; i++) printf("%02x", out[i]);
	printf("\n");
	return 0;
}
