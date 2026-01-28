
const Salsa20 = require('./Salsa20');

function main() {
    const key = new Uint8Array(32);
    for(let i=0; i<32; i++) key[i] = i+1;

    const nonce = new Uint8Array([3, 4, 5, 6, 7, 8, 9, 10]);
    const plaintext = "Hello World!";
    
    console.log("Plaintext: " + plaintext);

    // Encrypt
    const salsa = new Salsa20(key, nonce);
    const ciphertext = salsa.crypt(plaintext);

    let hex = "";
    for (let i = 0; i < ciphertext.length; i++) {
        let h = ciphertext[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    console.log("Ciphertext: " + hex);

    // Decrypt
    const salsaDec = new Salsa20(key, nonce);
    const decrypted = salsaDec.crypt(ciphertext);
    const decryptedText = new TextDecoder().decode(decrypted);

    console.log("Decrypted: " + decryptedText);

    if (plaintext === decryptedText) {
        console.log("Verification Passed!");
    } else {
        console.log("Verification Failed!");
    }
}

main();
