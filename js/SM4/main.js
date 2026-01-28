
const SM4 = require('./SM4');

function main() {
    const key = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
    const input = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
    const output = new Uint8Array(16);
    
    console.log(Array.from(input).map(b => b.toString(16).padStart(2, '0')).join(' ') + " ");

    const sm4 = new SM4();

    // ECB Encrypt
    sm4.setkey_enc(key);
    sm4.crypt_ecb(input, output);
    console.log(Array.from(output).map(b => b.toString(16).padStart(2, '0')).join(' ') + " ");

    // ECB Decrypt
    sm4.setkey_dec(key);
    sm4.crypt_ecb(output, output);
    console.log(Array.from(output).map(b => b.toString(16).padStart(2, '0')).join(' ') + " ");

    // CBC Encrypt
    const iv = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
    sm4.setkey_enc(key);
    sm4.crypt_cbc(iv, input, output);
    console.log(Array.from(output).map(b => b.toString(16).padStart(2, '0')).join(' ') + " ");

    // CBC Decrypt
    const iv_ = new Uint8Array([0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10]);
    sm4.setkey_dec(key);
    sm4.crypt_cbc(iv_, output, output);
    console.log(Array.from(output).map(b => b.toString(16).padStart(2, '0')).join(' ') + " ");
}

main();
