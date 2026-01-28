
// ECC.js
// Ported from c/ECC/ECC.c (targeting secp256r1)

const crypto = require('crypto');

// Curve parameters for secp256r1 (NIST P-256)
const Curve_P = 0xFFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFFn;
const Curve_A = -3n; // a = -3
const Curve_B = 0x5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604Bn;
const Curve_N = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551n;
const Curve_Gx = 0x6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296n;
const Curve_Gy = 0x4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5n;

const ECC_BYTES = 32;

// Helper: Modulo that handles negative numbers
function mod(n, m) {
    return ((n % m) + m) % m;
}

// Helper: Modular Inverse using Fermat's Little Theorem (since P is prime)
function modInverse(a, m) {
    return modPow(a, m - 2n, m);
}

// Helper: Modular Exponentiation
function modPow(base, exponent, modulus) {
    if (modulus === 1n) return 0n;
    let result = 1n;
    base = mod(base, modulus);
    while (exponent > 0n) {
        if (exponent % 2n === 1n) result = mod(result * base, modulus);
        exponent = exponent >> 1n;
        base = mod(base * base, modulus);
    }
    return result;
}

// Helper: Modular Square Root (Tonelli-Shanks is general, but for P = 3 mod 4, it's easier)
// For P-256, P = 2^256 - 2^224 + 2^192 + 2^96 - 1.
// P % 4 == 3. So we can use a = a^((P+1)/4) mod P.
function modSqrt(a, p) {
    return modPow(a, (p + 1n) / 4n, p);
}

class Point {
    constructor(x, y) {
        this.x = x;
        this.y = y;
    }

    isZero() {
        return this.x === null && this.y === null;
    }
}

const G = new Point(Curve_Gx, Curve_Gy);

// Point Addition (Affine)
function pointAdd(P, Q) {
    if (P.isZero()) return Q;
    if (Q.isZero()) return P;

    if (P.x === Q.x && P.y !== Q.y) {
        return new Point(null, null); // Infinity
    }

    let m;
    if (P.x === Q.x && P.y === Q.y) {
        // Point Doubling
        // m = (3x^2 + a) / 2y
        const num = mod(3n * P.x * P.x + Curve_A, Curve_P);
        const den = modInverse(2n * P.y, Curve_P);
        m = mod(num * den, Curve_P);
    } else {
        // Point Addition
        // m = (y2 - y1) / (x2 - x1)
        const num = mod(Q.y - P.y, Curve_P);
        const den = modInverse(Q.x - P.x, Curve_P);
        m = mod(num * den, Curve_P);
    }

    const x3 = mod(m * m - P.x - Q.x, Curve_P);
    const y3 = mod(m * (P.x - x3) - P.y, Curve_P);

    return new Point(x3, y3);
}

// Scalar Multiplication (Double and Add)
// Note: Not constant time, but sufficient for functional verification.
function pointMultiply(P, k) {
    let R = new Point(null, null); // Infinity
    let Q = P;

    while (k > 0n) {
        if (k & 1n) {
            R = pointAdd(R, Q);
        }
        Q = pointAdd(Q, Q);
        k >>= 1n;
    }
    return R;
}

// Convert BigInt to Buffer (32 bytes, Big Endian)
function bigIntToBuffer(n) {
    let hex = n.toString(16);
    if (hex.length % 2) hex = '0' + hex;
    const len = hex.length / 2;
    if (len > ECC_BYTES) {
        // Truncate or error? C code just writes bytes.
        // Assuming n fits in ECC_BYTES or we take last bytes.
        // But for keys, they should fit.
    }
    const buf = Buffer.alloc(ECC_BYTES);
    const src = Buffer.from(hex, 'hex');
    // Copy to end of buf
    src.copy(buf, ECC_BYTES - src.length);
    return buf;
}

// Convert Buffer to BigInt
function bufferToBigInt(buf) {
    return BigInt('0x' + buf.toString('hex'));
}

// Public API matching C functions

function ecc_make_key() {
    let privKey;
    do {
        const bytes = crypto.randomBytes(ECC_BYTES);
        privKey = bufferToBigInt(bytes);
    } while (privKey === 0n || privKey >= Curve_N);

    const pubPoint = pointMultiply(G, privKey);

    // Format output
    // Private Key: 32 bytes
    const p_privateKey = bigIntToBuffer(privKey);

    // Public Key: 33 bytes (compressed)
    // 0x02 if y is even, 0x03 if y is odd
    const prefix = (pubPoint.y & 1n) ? 0x03 : 0x02;
    const p_publicKey = Buffer.concat([
        Buffer.from([prefix]),
        bigIntToBuffer(pubPoint.x)
    ]);

    return {
        privateKey: p_privateKey,
        publicKey: p_publicKey
    };
}

function ecdh_shared_secret(p_publicKey, p_privateKey) {
    const privKey = bufferToBigInt(p_privateKey);
    
    // Decompress public key
    const prefix = p_publicKey[0];
    const x = bufferToBigInt(p_publicKey.slice(1));
    
    // Calculate y^2 = x^3 + ax + b
    const rhs = mod(x * x * x + Curve_A * x + Curve_B, Curve_P);
    let y = modSqrt(rhs, Curve_P);
    
    // Check parity
    const isOdd = (y & 1n) === 1n;
    const expectOdd = (prefix === 0x03);
    
    if (isOdd !== expectOdd) {
        y = Curve_P - y;
    }
    
    const pubPoint = new Point(x, y);
    
    // Compute shared secret: x coordinate of (privKey * pubPoint)
    const secretPoint = pointMultiply(pubPoint, privKey);
    
    return bigIntToBuffer(secretPoint.x);
}

function ecdsa_sign(p_privateKey, p_hash) {
    const d = bufferToBigInt(p_privateKey);
    const e = bufferToBigInt(p_hash); // Hash is treated as integer
    
    // e should be truncated if bit length > N bit length (both 256 here)
    
    let k, r, s;
    
    do {
        do {
            const bytes = crypto.randomBytes(ECC_BYTES);
            k = bufferToBigInt(bytes);
        } while (k === 0n || k >= Curve_N);
        
        const P_point = pointMultiply(G, k);
        r = mod(P_point.x, Curve_N);
    } while (r === 0n);
    
    const kInv = modInverse(k, Curve_N);
    s = mod(kInv * (e + r * d), Curve_N);
    
    if (s === 0n) return ecdsa_sign(p_privateKey, p_hash); // Retry if s is 0
    
    return Buffer.concat([bigIntToBuffer(r), bigIntToBuffer(s)]);
}

function ecdsa_verify(p_publicKey, p_hash, p_signature) {
    const r = bufferToBigInt(p_signature.slice(0, ECC_BYTES));
    const s = bufferToBigInt(p_signature.slice(ECC_BYTES));
    const e = bufferToBigInt(p_hash);
    
    if (r <= 0n || r >= Curve_N || s <= 0n || s >= Curve_N) return false;
    
    // Decompress public key
    const prefix = p_publicKey[0];
    const x = bufferToBigInt(p_publicKey.slice(1));
    const rhs = mod(x * x * x + Curve_A * x + Curve_B, Curve_P);
    let y = modSqrt(rhs, Curve_P);
    const isOdd = (y & 1n) === 1n;
    const expectOdd = (prefix === 0x03);
    if (isOdd !== expectOdd) y = Curve_P - y;
    const Q = new Point(x, y);
    
    const w = modInverse(s, Curve_N);
    const u1 = mod(e * w, Curve_N);
    const u2 = mod(r * w, Curve_N);
    
    const P1 = pointMultiply(G, u1);
    const P2 = pointMultiply(Q, u2);
    const R = pointAdd(P1, P2);
    
    if (R.isZero()) return false;
    
    const v = mod(R.x, Curve_N);
    return v === r;
}

module.exports = {
    ECC_BYTES,
    ecc_make_key,
    ecdh_shared_secret,
    ecdsa_sign,
    ecdsa_verify
};
