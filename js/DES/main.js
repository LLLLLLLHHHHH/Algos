
const DES = require('./DES');

function print_hex(label, data) {
    console.log(`${label}: ${Buffer.from(data).toString('hex').toUpperCase()}`);
}

function test_ecb() {
    console.log("Testing ECB...");
    const key = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    const plain = Buffer.from("Now is the time ", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new DES.DES_ctx();
    DES.DES_init(ctx, key);

    DES.DES_ECB_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    DES.DES_ECB_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("ECB Test Passed\n");
    } else {
        console.log("ECB Test FAILED\n");
    }
}

function test_cbc() {
    console.log("Testing CBC...");
    const key = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    const iv = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]);
    const plain = Buffer.from("Basic CBC Test!!", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new DES.DES_ctx();
    
    // Encrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_CBC_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_CBC_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("CBC Test Passed\n");
    } else {
        console.log("CBC Test FAILED\n");
    }
}

function test_ctr() {
    console.log("Testing CTR...");
    const key = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    const iv = new Uint8Array([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7]);
    const plain = Buffer.from("Counter Mode Tst", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new DES.DES_ctx();
    
    // Encrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_CTR_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_CTR_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("CTR Test Passed\n");
    } else {
        console.log("CTR Test FAILED\n");
    }
}

function test_cfb() {
    console.log("Testing CFB...");
    const key = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    const iv = new Uint8Array([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);
    const plain = Buffer.from("CFB Mode Test!!!", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new DES.DES_ctx();
    
    // Encrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_CFB_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_CFB_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("CFB Test Passed\n");
    } else {
        console.log("CFB Test FAILED\n");
    }
}

function test_ofb() {
    console.log("Testing OFB...");
    const key = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF]);
    const iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const plain = Buffer.from("OFB Mode Test!!!", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new DES.DES_ctx();
    
    // Encrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_OFB_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    DES.DES_init_iv(ctx, key, iv);
    DES.DES_OFB_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("OFB Test Passed\n");
    } else {
        console.log("OFB Test FAILED\n");
    }
}

test_ecb();
test_cbc();
test_ctr();
test_cfb();
test_ofb();
