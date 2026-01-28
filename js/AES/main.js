
const AES = require('./AES');

function phex(str) {
    let output = "";
    for (let i = 0; i < str.length; ++i) {
        let hex = str[i].toString(16);
        if (hex.length < 2) hex = "0" + hex;
        output += hex;
    }
    console.log(output);
}

function main() {
    const key = new Uint8Array([
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c
    ]);
    
    const in_data = new Uint8Array([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a,
        0xae, 0x2d, 0x8a, 0x57, 0x1e, 0x03, 0xac, 0x9c, 0x9e, 0xb7, 0x6f, 0xac, 0x45, 0xaf, 0x8e, 0x51,
        0x30, 0xc8, 0x1c, 0x46, 0xa3, 0x5c, 0xe4, 0x11, 0xe5, 0xfb, 0xc1, 0x19, 0x1a, 0x0a, 0x52, 0xef,
        0xf6, 0x9f, 0x24, 0x45, 0xdf, 0x4f, 0x9b, 0x17, 0xad, 0x2b, 0x41, 0x7b, 0xe6, 0x6c, 0x37, 0x10 
    ]);

    const iv = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f
    ]);

    let ctx = new AES.AES_ctx();

    // Original
    // phex(in_data.subarray(0, 16)); // C code prints 16 bytes. Wait, C code phex takes len.
    // main.c: phex(in, 16);
    phex(in_data.subarray(0, 16));

    // ECB Encrypt
    AES.AES_init_ctx(ctx, key);
    AES.AES_ECB_encrypt_buffer(ctx, in_data); // Encrypts first 16 bytes
    phex(in_data.subarray(0, 16));

    // ECB Decrypt
    AES.AES_ECB_decrypt_buffer(ctx, in_data);
    phex(in_data.subarray(0, 16));

    // CBC Encrypt
    AES.AES_init_ctx_iv(ctx, key, iv);
    AES.AES_CBC_encrypt_buffer(ctx, in_data, 64);
    phex(in_data.subarray(0, 16)); // C code prints 16 bytes: phex(in, 16);

    // CBC Decrypt
    AES.AES_init_ctx_iv(ctx, key, iv);
    AES.AES_CBC_decrypt_buffer(ctx, in_data, 64);
    phex(in_data.subarray(0, 16));

    // CTR Encrypt
    AES.AES_init_ctx_iv(ctx, key, iv);
    AES.AES_CTR_xcrypt_buffer(ctx, in_data, 64);
    phex(in_data.subarray(0, 16));

    // CTR Decrypt (same function)
    AES.AES_init_ctx_iv(ctx, key, iv);
    AES.AES_CTR_xcrypt_buffer(ctx, in_data, 64);
    phex(in_data.subarray(0, 16));
}

main();
