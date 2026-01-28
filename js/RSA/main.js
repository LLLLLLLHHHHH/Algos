
const RSA = require('./RSA');
const keys = require('./keys');

function printHex(data) {
    let hex = '';
    for (let i = 0; i < data.length; i++) {
        let h = data[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    console.log(hex + '\n');
}

function main() {
    console.log("RSA2048 JS Test\n");

    const KEY_M_BITS = 2048;

    // Load Keys
    const pk = new RSA.RsaPublicKey(
        KEY_M_BITS,
        keys.key_m,
        keys.key_e
    );

    const sk = new RSA.RsaPrivateKey(
        KEY_M_BITS,
        keys.key_m,
        keys.key_e, // public_exponent
        keys.key_pe, // exponent (d)
        keys.key_p1,
        keys.key_p2,
        keys.key_e1,
        keys.key_e2,
        keys.key_c
    );

    const input = new Uint8Array([0x21, 0x55, 0x53, 0x53, 0x53, 0x53]); // "!USSSS"
    
    // 1. Public Encrypt
    // Note: Padding is random, so output won't match C exactly, but decryption should work.
    console.log("Public Encrypt:");
    const output1 = RSA.rsa_public_encrypt(input, pk);
    printHex(output1);

    // 2. Private Decrypt
    console.log("Private Decrypt:");
    const msg1 = RSA.rsa_private_decrypt(output1, sk);
    printHex(msg1);

    // 3. Private Encrypt (Signing)
    console.log("Private Encrypt (Sign):");
    const output2 = RSA.rsa_private_encrypt(input, sk);
    printHex(output2);

    // 4. Public Decrypt (Verification)
    console.log("Public Decrypt (Verify):");
    const msg2 = RSA.rsa_public_decrypt(output2, pk);
    printHex(msg2);
}

main();
