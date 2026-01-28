
// SM2.js
// Ported from c/SM2/SM2.c

class SM2 {
    constructor() {
        // SM2 Parameters (BigInt)
        this.p = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFFn;
        this.a = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFCn;
        this.b = 0x28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93n;
        this.n = 0xFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123n;
        this.Gx = 0x32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7n;
        this.Gy = 0xBC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0n;
    }

    // Modular arithmetic
    mod(a, m) {
        const res = a % m;
        return res >= 0n ? res : res + m;
    }

    modInverse(a, m) {
        a = this.mod(a, m); // Ensure a is positive and < m
        let [old_r, r] = [a, m];
        let [old_s, s] = [1n, 0n];
        let [old_t, t] = [0n, 1n];

        while (r !== 0n) {
            const quotient = old_r / r;
            [old_r, r] = [r, old_r - quotient * r];
            [old_s, s] = [s, old_s - quotient * s];
            [old_t, t] = [t, old_t - quotient * t];
        }

        return this.mod(old_s, m);
    }

    // Point arithmetic
    pointAdd(P, Q) {
        if (!P) return Q;
        if (!Q) return P;

        const { x: x1, y: y1 } = P;
        const { x: x2, y: y2 } = Q;

        if (x1 === x2 && y1 !== y2) {
            return null; // Infinity
        }

        let lambda;
        if (x1 === x2 && y1 === y2) {
            // Point doubling
            // lambda = (3 * x1^2 + a) * (2 * y1)^-1 mod p
            const num = this.mod(3n * x1 * x1 + this.a, this.p);
            const den = this.modInverse(2n * y1, this.p);
            lambda = this.mod(num * den, this.p);
        } else {
            // Point addition
            // lambda = (y2 - y1) * (x2 - x1)^-1 mod p
            const num = this.mod(y2 - y1, this.p);
            const den = this.modInverse(x2 - x1, this.p);
            lambda = this.mod(num * den, this.p);
        }

        const x3 = this.mod(lambda * lambda - x1 - x2, this.p);
        const y3 = this.mod(lambda * (x1 - x3) - y1, this.p);

        return { x: x3, y: y3 };
    }

    pointMultiply(P, k) {
        let R = null; // Infinity
        let Q = P;

        while (k > 0n) {
            if (k & 1n) {
                R = this.pointAdd(R, Q);
            }
            Q = this.pointAdd(Q, Q);
            k >>= 1n;
        }

        return R;
    }

    // ECDSA Sign
    // Input: privateKey (BigInt), random k (BigInt), hash (BigInt)
    // Output: { r: BigInt, s: BigInt }
    sign(privateKey, k, hash) {
        if (k < 1n || k >= this.n) throw new Error("Invalid random number k");

        // 1. Compute (x1, y1) = [k]G
        const P = this.pointMultiply({ x: this.Gx, y: this.Gy }, k);
        const x1 = P.x;

        // 2. r = (e + x1) mod n
        const r = this.mod(hash + x1, this.n);

        if (r === 0n || this.mod(r + k, this.n) === 0n) {
            throw new Error("Invalid r (need new k)");
        }

        // 3. s = ((1 + d)^-1 * (k - r * d)) mod n
        const d = privateKey;
        const inv_1_plus_d = this.modInverse(1n + d, this.n);
        const k_minus_rd = this.mod(k - r * d, this.n);
        const s = this.mod(inv_1_plus_d * k_minus_rd, this.n);

        if (s === 0n) throw new Error("Invalid s (need new k)");

        return { r, s };
    }

    // ECDSA Verify
    // Input: publicKey (Point), hash (BigInt), r (BigInt), s (BigInt)
    // Output: boolean
    verify(publicKey, hash, r, s) {
        if (r < 1n || r >= this.n || s < 1n || s >= this.n) return false;

        // 1. t = (r + s) mod n
        const t = this.mod(r + s, this.n);
        if (t === 0n) return false;

        // 2. (x1, y1) = [s]G + [t]PA
        const sG = this.pointMultiply({ x: this.Gx, y: this.Gy }, s);
        const tP = this.pointMultiply(publicKey, t);
        const P = this.pointAdd(sG, tP);

        if (!P) return false;

        // 3. R = (e + x1) mod n
        const R = this.mod(hash + P.x, this.n);

        return R === r;
    }

    // Helper: Convert Little Endian Byte Array to BigInt
    static fromLeBytes(bytes) {
        let val = 0n;
        let mul = 1n;
        for (let i = 0; i < bytes.length; i++) {
            val += BigInt(bytes[i]) * mul;
            mul <<= 8n;
        }
        return val;
    }

    // Helper: Convert BigInt to Little Endian Byte Array (32 bytes)
    static toLeBytes(val) {
        const bytes = new Uint8Array(32);
        for (let i = 0; i < 32; i++) {
            bytes[i] = Number(val & 0xFFn);
            val >>= 8n;
        }
        return bytes;
    }
}

module.exports = SM2;
