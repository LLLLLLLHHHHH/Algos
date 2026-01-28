
// SHA256.js
// Ported from c/SHA256/SHA256.c

class SHA256 {
    constructor() {
        this.reset();
    }

    reset() {
        this.buf = new Uint8Array(64);
        this.hash = new Uint32Array(8);
        this.bits = new Uint32Array(2); // [low, high]
        this.len = 0;
        this.W = new Uint32Array(64);

        this.hash[0] = 0x6a09e667;
        this.hash[1] = 0xbb67ae85;
        this.hash[2] = 0x3c6ef372;
        this.hash[3] = 0xa54ff53a;
        this.hash[4] = 0x510e527f;
        this.hash[5] = 0x9b05688c;
        this.hash[6] = 0x1f83d9ab;
        this.hash[7] = 0x5be0cd19;

        this.bits[0] = 0;
        this.bits[1] = 0;
    }

    // Constants
    static K = new Uint32Array([
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    ]);

    // Rotates right
    static _r(x, n) {
        return (x >>> n) | (x << (32 - n));
    }

    static _Ch(x, y, z) {
        return (x & y) ^ ((~x) & z);
    }

    static _Ma(x, y, z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    static _S0(x) {
        return SHA256._r(x, 2) ^ SHA256._r(x, 13) ^ SHA256._r(x, 22);
    }

    static _S1(x) {
        return SHA256._r(x, 6) ^ SHA256._r(x, 11) ^ SHA256._r(x, 25);
    }

    static _G0(x) {
        return SHA256._r(x, 7) ^ SHA256._r(x, 18) ^ (x >>> 3);
    }

    static _G1(x) {
        return SHA256._r(x, 17) ^ SHA256._r(x, 19) ^ (x >>> 10);
    }

    _word(c, offset) {
        return (c[offset] << 24) | (c[offset + 1] << 16) | (c[offset + 2] << 8) | c[offset + 3];
    }

    _addbits(n) {
        if (this.bits[0] > (0xffffffff - n)) {
            this.bits[1] = (this.bits[1] + 1) >>> 0;
        }
        this.bits[0] = (this.bits[0] + n) >>> 0;
    }

    _process() {
        let a, b, c, d, e, f, g, h;
        let t0, t1;

        a = this.hash[0];
        b = this.hash[1];
        c = this.hash[2];
        d = this.hash[3];
        e = this.hash[4];
        f = this.hash[5];
        g = this.hash[6];
        h = this.hash[7];

        for (let i = 0; i < 64; i++) {
            if (i < 16) {
                this.W[i] = (this.buf[i * 4] << 24) | (this.buf[i * 4 + 1] << 16) | (this.buf[i * 4 + 2] << 8) | this.buf[i * 4 + 3];
            } else {
                this.W[i] = (SHA256._G1(this.W[i - 2]) + this.W[i - 7] + SHA256._G0(this.W[i - 15]) + this.W[i - 16]) >>> 0;
            }

            t0 = (h + SHA256._S1(e) + SHA256._Ch(e, f, g) + SHA256.K[i] + this.W[i]) >>> 0;
            t1 = (SHA256._S0(a) + SHA256._Ma(a, b, c)) >>> 0;

            h = g;
            g = f;
            f = e;
            e = (d + t0) >>> 0;
            d = c;
            c = b;
            b = a;
            a = (t0 + t1) >>> 0;
        }

        this.hash[0] = (this.hash[0] + a) >>> 0;
        this.hash[1] = (this.hash[1] + b) >>> 0;
        this.hash[2] = (this.hash[2] + c) >>> 0;
        this.hash[3] = (this.hash[3] + d) >>> 0;
        this.hash[4] = (this.hash[4] + e) >>> 0;
        this.hash[5] = (this.hash[5] + f) >>> 0;
        this.hash[6] = (this.hash[6] + g) >>> 0;
        this.hash[7] = (this.hash[7] + h) >>> 0;
    }

    update(input) {
        let inputBytes;
        if (typeof input === 'string') {
            inputBytes = new Uint8Array(input.length);
            for (let i = 0; i < input.length; i++) {
                inputBytes[i] = input.charCodeAt(i);
            }
        } else {
            inputBytes = input;
        }

        const len = inputBytes.length;
        for (let i = 0; i < len; i++) {
            this.buf[this.len++] = inputBytes[i];
            if (this.len === 64) {
                this._process();
                this._addbits(512);
                this.len = 0;
            }
        }
    }

    finish() {
        const j = this.len % 64;
        this.buf[j] = 0x80;
        
        for (let i = j + 1; i < 64; i++) {
            this.buf[i] = 0x00;
        }

        if (this.len > 55) {
            this._process();
            for (let i = 0; i < 64; i++) {
                this.buf[i] = 0x00;
            }
        }

        this._addbits(this.len * 8);

        // Append length (Big Endian)
        // High 32 bits
        this.buf[56] = (this.bits[1] >>> 24) & 0xFF;
        this.buf[57] = (this.bits[1] >>> 16) & 0xFF;
        this.buf[58] = (this.bits[1] >>> 8) & 0xFF;
        this.buf[59] = this.bits[1] & 0xFF;

        // Low 32 bits
        this.buf[60] = (this.bits[0] >>> 24) & 0xFF;
        this.buf[61] = (this.bits[0] >>> 16) & 0xFF;
        this.buf[62] = (this.bits[0] >>> 8) & 0xFF;
        this.buf[63] = this.bits[0] & 0xFF;

        this._process();

        const digest = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            digest[i * 4] = (this.hash[i] >>> 24) & 0xFF;
            digest[i * 4 + 1] = (this.hash[i] >>> 16) & 0xFF;
            digest[i * 4 + 2] = (this.hash[i] >>> 8) & 0xFF;
            digest[i * 4 + 3] = this.hash[i] & 0xFF;
        }

        return digest;
    }
}

module.exports = SHA256;
