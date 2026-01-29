
const TDES = require('./3DES');

function print_hex(label, data) {
    console.log(`${label}: ${Buffer.from(data).toString('hex').toUpperCase()}`);
}

function test_ecb() {
    console.log("Testing 3DES ECB...");
    const key = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, // K1
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, // K2
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23  // K3
    ]);
    const plain = Buffer.from("ThreeKeyTripleD!", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new TDES.TDES_ctx();
    TDES.TDES_init(ctx, key);

    TDES.TDES_ECB_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    TDES.TDES_ECB_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("ECB Test Passed\n");
    } else {
        console.log("ECB Test FAILED\n");
    }
}

function test_cbc() {
    console.log("Testing 3DES CBC...");
    const key = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF // K3 = K1
    ]);
    const iv = new Uint8Array([0x12, 0x34, 0x56, 0x78, 0x90, 0xAB, 0xCD, 0xEF]);
    const plain = Buffer.from("3DES CBC Test!!!", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new TDES.TDES_ctx();
    
    // Encrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_CBC_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_CBC_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("CBC Test Passed\n");
    } else {
        console.log("CBC Test FAILED\n");
    }
}

function test_ctr() {
    console.log("Testing 3DES CTR...");
    const key = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    ]);
    const iv = new Uint8Array([0xF0, 0xF1, 0xF2, 0xF3, 0xF4, 0xF5, 0xF6, 0xF7]);
    const plain = Buffer.from("Counter Mode 3DE", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new TDES.TDES_ctx();
    
    // Encrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_CTR_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_CTR_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("CTR Test Passed\n");
    } else {
        console.log("CTR Test FAILED\n");
    }
}

function test_cfb() {
    console.log("Testing 3DES CFB...");
    const key = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    ]);
    const iv = new Uint8Array([0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10]);
    const plain = Buffer.from("CFB Mode Test 3D", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new TDES.TDES_ctx();
    
    // Encrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_CFB_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_CFB_decrypt_buffer(ctx, buf);
    print_hex("Decrypted", buf);

    if (Buffer.compare(plain, buf) === 0) {
        console.log("CFB Test Passed\n");
    } else {
        console.log("CFB Test FAILED\n");
    }
}

function test_ofb() {
    console.log("Testing 3DES OFB...");
    const key = new Uint8Array([
        0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
        0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01,
        0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF, 0x01, 0x23
    ]);
    const iv = new Uint8Array([0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00]);
    const plain = Buffer.from("OFB Mode Test 3D", "utf8");
    const buf = new Uint8Array(plain);

    const ctx = new TDES.TDES_ctx();
    
    // Encrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_OFB_encrypt_buffer(ctx, buf);
    print_hex("Cipher", buf);

    // Decrypt
    TDES.TDES_init_iv(ctx, key, iv);
    TDES.TDES_OFB_decrypt_buffer(ctx, buf);
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
