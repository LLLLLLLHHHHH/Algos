
const RC4 = require('./RC4');

function main() {
    const rc4 = new RC4();
    
    // Test case from C main.c
    // char data[] = "nothing";
    // const char *key = "123";
    
    let data = "nothing";
    const key = "123";
    
    // Encrypt
    let encrypted = rc4.encrypt(data, key);
    
    // In C, printf("%s", data) might print garbage if encrypted bytes are not printable or contain nulls.
    // "nothing" encrypted with "123":
    // n(110) ^ k ...
    
    // Let's print bytes for verification as string might be messy
    // But to match C output structure:
    console.log("加密值:", encrypted); // Might look like garbage
    
    // Decrypt (RC4 is symmetric)
    // Pass the encrypted string (or bytes) back
    // Note: If encrypted string has issues with encoding, this might fail.
    // In JS, String.fromCharCode creates a string of UTF-16 code units (0-65535).
    // Our bytes are 0-255. This is safe for 1:1 mapping (Latin1).
    
    let decrypted = rc4.encrypt(encrypted, key);
    console.log("解密值:", decrypted);
}

main();
