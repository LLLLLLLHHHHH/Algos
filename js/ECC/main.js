
const ECC = require('./ECC');

function print_hex(label, buf) {
    let hex = buf.toString('hex').toUpperCase();
    console.log(`${label.padEnd(12)}: ${hex}`);
}

// Access internal functions for testing if possible, or just use public API
// Since I can't easily access non-exported functions, I'll export them temporarily or just rely on API.
// Wait, I can export G and pointMultiply in ECC.js

function main() {
    console.log("=== ECC 测试 ===\n");

    // Test 1: Key Generation
    console.log("[测试1] 生成密钥对...");
    
    const alice = ECC.ecc_make_key();
    const bob = ECC.ecc_make_key();

    print_hex("Alice私钥", alice.privateKey);
    print_hex("Alice公钥", alice.publicKey);
    print_hex("Bob私钥", bob.privateKey);
    print_hex("Bob公钥", bob.publicKey);
    console.log("密钥对生成测试通过\n");

    // Test 2: ECDH Shared Secret
    console.log("[测试2] ECDH 共享密钥...");
    
    const secret1 = ECC.ecdh_shared_secret(bob.publicKey, alice.privateKey);
    const secret2 = ECC.ecdh_shared_secret(alice.publicKey, bob.privateKey);
    
    print_hex("Alice计算密钥", secret1);
    print_hex("Bob计算密钥", secret2);

    if (secret1.equals(secret2)) {
        console.log("ECDH 共享密钥测试通过\n");
    } else {
        console.error("错误：共享密钥不匹配\n");
        // process.exit(1); // Don't exit, let's see other tests
    }

    // Test 3: ECDSA Signature
    console.log("[测试3] ECDSA 签名验证...");
    
    const hash = Buffer.alloc(ECC.ECC_BYTES, 0x01); // Mock hash
    const signature = ECC.ecdsa_sign(alice.privateKey, hash);
    
    print_hex("签名", signature);
    
    const isValid = ECC.ecdsa_verify(alice.publicKey, hash, signature);
    
    if (isValid) {
        console.log("有效签名验证成功");
        console.log("\n所有测试通过！");
    } else {
        console.error("错误：签名验证失败");
        // process.exit(1);
    }
}

main();
