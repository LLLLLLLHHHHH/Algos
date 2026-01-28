
// RSA.js
// Ported from c/RSA/RSA.c

const crypto = require('crypto');

// Helper: Convert Uint8Array to BigInt
function bufferToBigInt(buf) {
    let hex = [];
    for (let i = 0; i < buf.length; i++) {
        let h = buf[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex.push(h);
    }
    if (hex.length === 0) return 0n;
    return BigInt('0x' + hex.join(''));
}

// Helper: Convert BigInt to Uint8Array (of specific length)
function bigIntToBuffer(val, length) {
    let hex = val.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    
    const buf = new Uint8Array(length);
    const byteLen = hex.length / 2;
    
    // Fill from the end
    for (let i = 0; i < byteLen && i < length; i++) {
        const byteVal = parseInt(hex.substring(hex.length - 2 - i * 2, hex.length - i * 2), 16);
        buf[length - 1 - i] = byteVal;
    }
    return buf;
}

// Modular Exponentiation: base^exp % mod
function modPow(base, exp, mod) {
    let res = 1n;
    base = base % mod;
    while (exp > 0n) {
        if (exp % 2n === 1n) res = (res * base) % mod;
        base = (base * base) % mod;
        exp /= 2n;
    }
    return res;
}

// Public Key Structure
class RsaPublicKey {
    constructor(bits, modulus, exponent) {
        this.bits = bits;
        this.modulus = bufferToBigInt(modulus); // n
        this.exponent = bufferToBigInt(exponent); // e
        this.modulusLen = (bits + 7) >> 3;
    }
}

// Private Key Structure
class RsaPrivateKey {
    constructor(bits, modulus, public_exponent, exponent, prime1, prime2, prime_exponent1, prime_exponent2, coefficient) {
        this.bits = bits;
        this.modulus = bufferToBigInt(modulus); // n
        this.public_exponent = bufferToBigInt(public_exponent); // e
        this.exponent = bufferToBigInt(exponent); // d
        this.p = bufferToBigInt(prime1);
        this.q = bufferToBigInt(prime2);
        this.dp = bufferToBigInt(prime_exponent1); // d mod (p-1)
        this.dq = bufferToBigInt(prime_exponent2); // d mod (q-1)
        this.qInv = bufferToBigInt(coefficient); // q^-1 mod p
        this.modulusLen = (bits + 7) >> 3;
    }
}

// Public Block Operation: c = m^e mod n
function publicBlockOperation(input, pk) {
    const m = bufferToBigInt(input);
    if (m >= pk.modulus) {
        throw new Error("Data too large for modulus");
    }
    const c = modPow(m, pk.exponent, pk.modulus);
    return bigIntToBuffer(c, pk.modulusLen);
}

// Private Block Operation (CRT): m = c^d mod n
function privateBlockOperation(input, sk) {
    const c = bufferToBigInt(input);
    if (c >= sk.modulus) {
        throw new Error("Data too large for modulus");
    }

    // CRT
    // m1 = c^dp mod p
    const cp = c % sk.p;
    const m1 = modPow(cp, sk.dp, sk.p);

    // m2 = c^dq mod q
    const cq = c % sk.q;
    const m2 = modPow(cq, sk.dq, sk.q);

    // h = qInv * (m1 - m2) mod p
    let h = (sk.qInv * (m1 - m2)) % sk.p;
    if (h < 0n) h += sk.p; // Handle negative result from subtraction

    // m = m2 + h * q
    const m = m2 + h * sk.q;

    return bigIntToBuffer(m, sk.modulusLen);
}

// RSA Public Encrypt (Block Type 2 Padding)
function rsa_public_encrypt(inData, pk) {
    const modulusLen = pk.modulusLen;
    const inLen = inData.length;

    if (inLen + 11 > modulusLen) {
        throw new Error("Data too long for RSA key size");
    }

    const pkcsBlock = new Uint8Array(modulusLen);
    
    // Block Type 2 Padding
    pkcsBlock[0] = 0;
    pkcsBlock[1] = 2;
    
    // Padding String (non-zero random bytes)
    const padLen = modulusLen - inLen - 3;
    for (let i = 0; i < padLen; i++) {
        let b;
        do {
            b = crypto.randomBytes(1)[0];
        } while (b === 0);
        pkcsBlock[2 + i] = b;
    }
    
    pkcsBlock[2 + padLen] = 0; // Separator
    pkcsBlock.set(inData, 2 + padLen + 1);

    return publicBlockOperation(pkcsBlock, pk);
}

// RSA Public Decrypt (Verification - Block Type 1 Padding Check)
// Note: C code `rsa_public_decrypt` checks for Block Type 1 (0x01) and padding 0xFF.
function rsa_public_decrypt(inData, pk) {
    const modulusLen = pk.modulusLen;
    if (inData.length > modulusLen) throw new Error("Input data too long");

    const pkcsBlock = publicBlockOperation(inData, pk);
    
    if (pkcsBlock.length !== modulusLen) throw new Error("Wrong block length");
    
    // Check Padding (Block Type 1)
    if (pkcsBlock[0] !== 0 || pkcsBlock[1] !== 1) {
        throw new Error("Wrong padding type");
    }

    let i;
    for (i = 2; i < modulusLen - 1; i++) {
        if (pkcsBlock[i] !== 0xFF) break;
    }

    if (pkcsBlock[i] !== 0) throw new Error("Padding check failed");
    i++; // Skip separator

    return pkcsBlock.slice(i);
}

// RSA Private Encrypt (Signing - Block Type 1 Padding)
function rsa_private_encrypt(inData, sk) {
    const modulusLen = sk.modulusLen;
    const inLen = inData.length;

    if (inLen + 11 > modulusLen) {
        throw new Error("Data too long for RSA key size");
    }

    const pkcsBlock = new Uint8Array(modulusLen);
    
    // Block Type 1 Padding
    pkcsBlock[0] = 0;
    pkcsBlock[1] = 1;
    
    // Padding String (0xFF)
    const padLen = modulusLen - inLen - 3;
    for (let i = 0; i < padLen; i++) {
        pkcsBlock[2 + i] = 0xFF;
    }
    
    pkcsBlock[2 + padLen] = 0; // Separator
    pkcsBlock.set(inData, 2 + padLen + 1);

    return privateBlockOperation(pkcsBlock, sk);
}

// RSA Private Decrypt (Decryption - Block Type 2 Padding Check)
function rsa_private_decrypt(inData, sk) {
    const modulusLen = sk.modulusLen;
    if (inData.length > modulusLen) throw new Error("Input data too long");

    const pkcsBlock = privateBlockOperation(inData, sk);
    
    if (pkcsBlock.length !== modulusLen) throw new Error("Wrong block length");

    // Check Padding (Block Type 2)
    if (pkcsBlock[0] !== 0 || pkcsBlock[1] !== 2) {
        throw new Error("Wrong padding type");
    }

    let i;
    for (i = 2; i < modulusLen - 1; i++) {
        if (pkcsBlock[i] === 0) break;
    }

    if (i >= modulusLen - 1) throw new Error("Padding separator not found");
    i++; // Skip separator

    return pkcsBlock.slice(i);
}

module.exports = {
    RsaPublicKey,
    RsaPrivateKey,
    rsa_public_encrypt,
    rsa_public_decrypt,
    rsa_private_encrypt,
    rsa_private_decrypt
};
