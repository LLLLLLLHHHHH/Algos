
# Salsa20 Implementation in C

This is a standard implementation of the Salsa20 stream cipher (Salsa20/20).

## Files

- `salsa20.h`: Header file with context struct and function prototypes.
- `salsa20.c`: Implementation of Salsa20.
- `main.c`: Test program.

## Usage

```c
#include "salsa20.h"

salsa20_context ctx;
uint8_t key[32] = { ... };
uint8_t nonce[8] = { ... };
uint8_t input[] = "Hello";
uint8_t output[5];

salsa20_init(&ctx, key, nonce);
salsa20_crypt(&ctx, input, output, 5);
```

## Build and Run

You can compile using any C compiler. For example:

```bash
gcc salsa20.c main.c -o salsa20_test
./salsa20_test
```
