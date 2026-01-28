
const ChaCha20 = require('./ChaCha20');

function main() {
    // RFC 7539 Test Vector
    const key = new Uint8Array([
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    ]);

    const nonce = new Uint8Array([
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a,
        0x00, 0x00, 0x00, 0x00
    ]);

    const counter = 1;

    const plaintext = "Ladies and Gentlemen of the class of '99: If I could offer you only one tip for the future, sunscreen would be it.";
    
    console.log("Plaintext: " + plaintext);

    // Encrypt
    const chacha = new ChaCha20(key, nonce, counter);
    const ciphertext = chacha.crypt(plaintext);

    let hex = "";
    for (let i = 0; i < ciphertext.length; i++) {
        let h = ciphertext[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    console.log("Ciphertext: " + hex);

    // Decrypt
    const chachaDec = new ChaCha20(key, nonce, counter);
    const decrypted = chachaDec.crypt(ciphertext);
    const decryptedText = new TextDecoder().decode(decrypted);

    console.log("Decrypted: " + decryptedText);

    // Verify
    const expectedStartHex = "6e2e359a2568f98041ba0728dd0d6981";
    if (hex.startsWith(expectedStartHex)) {
        console.log("Verification Passed!");
    } else {
        console.log("Verification Failed!");
    }
}

main();
