
// MD5.js
// Ported from c/MD5/MD5.c

class MD5 {
    constructor() {
        this.reset();
    }

    reset() {
        this.count = [0, 0]; // uint32_t count[2] (bits count)
        this.state = new Uint32Array(4); // uint32_t state[4]
        this.buffer = new Uint8Array(64); // uint8_t buffer[64]

        this.state[0] = 0x67452301;
        this.state[1] = 0xEFCDAB89;
        this.state[2] = 0x98BADCFE;
        this.state[3] = 0x10325476;
    }

    // F, G, H, I functions
    static F(x, y, z) { return (x & y) | (~x & z); }
    static G(x, y, z) { return (x & z) | (y & ~z); }
    static H(x, y, z) { return x ^ y ^ z; }
    static I(x, y, z) { return y ^ (x | ~z); }

    static ROTATE_LEFT(x, n) {
        return (x << n) | (x >>> (32 - n));
    }

    static FF(a, b, c, d, x, s, ac) {
        a += MD5.F(b, c, d) + x + ac;
        a = MD5.ROTATE_LEFT(a, s);
        a += b;
        return a; // Return modified a
    }

    static GG(a, b, c, d, x, s, ac) {
        a += MD5.G(b, c, d) + x + ac;
        a = MD5.ROTATE_LEFT(a, s);
        a += b;
        return a;
    }

    static HH(a, b, c, d, x, s, ac) {
        a += MD5.H(b, c, d) + x + ac;
        a = MD5.ROTATE_LEFT(a, s);
        a += b;
        return a;
    }

    static II(a, b, c, d, x, s, ac) {
        a += MD5.I(b, c, d) + x + ac;
        a = MD5.ROTATE_LEFT(a, s);
        a += b;
        return a;
    }

    // Transform state based on block
    transform(block) {
        let a = this.state[0];
        let b = this.state[1];
        let c = this.state[2];
        let d = this.state[3];
        let x = new Uint32Array(16);

        // Decode block into x (Little Endian)
        for (let i = 0, j = 0; j < 64; i++, j += 4) {
            x[i] = block[j] | (block[j + 1] << 8) | (block[j + 2] << 16) | (block[j + 3] << 24);
        }

        /* Round 1 */
        a = MD5.FF(a, b, c, d, x[0], 7, 0xd76aa478); /* 1 */
        d = MD5.FF(d, a, b, c, x[1], 12, 0xe8c7b756); /* 2 */
        c = MD5.FF(c, d, a, b, x[2], 17, 0x242070db); /* 3 */
        b = MD5.FF(b, c, d, a, x[3], 22, 0xc1bdceee); /* 4 */
        a = MD5.FF(a, b, c, d, x[4], 7, 0xf57c0faf); /* 5 */
        d = MD5.FF(d, a, b, c, x[5], 12, 0x4787c62a); /* 6 */
        c = MD5.FF(c, d, a, b, x[6], 17, 0xa8304613); /* 7 */
        b = MD5.FF(b, c, d, a, x[7], 22, 0xfd469501); /* 8 */
        a = MD5.FF(a, b, c, d, x[8], 7, 0x698098d8); /* 9 */
        d = MD5.FF(d, a, b, c, x[9], 12, 0x8b44f7af); /* 10 */
        c = MD5.FF(c, d, a, b, x[10], 17, 0xffff5bb1); /* 11 */
        b = MD5.FF(b, c, d, a, x[11], 22, 0x895cd7be); /* 12 */
        a = MD5.FF(a, b, c, d, x[12], 7, 0x6b901122); /* 13 */
        d = MD5.FF(d, a, b, c, x[13], 12, 0xfd987193); /* 14 */
        c = MD5.FF(c, d, a, b, x[14], 17, 0xa679438e); /* 15 */
        b = MD5.FF(b, c, d, a, x[15], 22, 0x49b40821); /* 16 */

        /* Round 2 */
        a = MD5.GG(a, b, c, d, x[1], 5, 0xf61e2562); /* 17 */
        d = MD5.GG(d, a, b, c, x[6], 9, 0xc040b340); /* 18 */
        c = MD5.GG(c, d, a, b, x[11], 14, 0x265e5a51); /* 19 */
        b = MD5.GG(b, c, d, a, x[0], 20, 0xe9b6c7aa); /* 20 */
        a = MD5.GG(a, b, c, d, x[5], 5, 0xd62f105d); /* 21 */
        d = MD5.GG(d, a, b, c, x[10], 9, 0x02441453); /* 22 */
        c = MD5.GG(c, d, a, b, x[15], 14, 0xd8a1e681); /* 23 */
        b = MD5.GG(b, c, d, a, x[4], 20, 0xe7d3fbc8); /* 24 */
        a = MD5.GG(a, b, c, d, x[9], 5, 0x21e1cde6); /* 25 */
        d = MD5.GG(d, a, b, c, x[14], 9, 0xc33707d6); /* 26 */
        c = MD5.GG(c, d, a, b, x[3], 14, 0xf4d50d87); /* 27 */
        b = MD5.GG(b, c, d, a, x[8], 20, 0x455a14ed); /* 28 */
        a = MD5.GG(a, b, c, d, x[13], 5, 0xa9e3e905); /* 29 */
        d = MD5.GG(d, a, b, c, x[2], 9, 0xfcefa3f8); /* 30 */
        c = MD5.GG(c, d, a, b, x[7], 14, 0x676f02d9); /* 31 */
        b = MD5.GG(b, c, d, a, x[12], 20, 0x8d2a4c8a); /* 32 */

        /* Round 3 */
        a = MD5.HH(a, b, c, d, x[5], 4, 0xfffa3942); /* 33 */
        d = MD5.HH(d, a, b, c, x[8], 11, 0x8771f681); /* 34 */
        c = MD5.HH(c, d, a, b, x[11], 16, 0x6d9d6122); /* 35 */
        b = MD5.HH(b, c, d, a, x[14], 23, 0xfde5380c); /* 36 */
        a = MD5.HH(a, b, c, d, x[1], 4, 0xa4beea44); /* 37 */
        d = MD5.HH(d, a, b, c, x[4], 11, 0x4bdecfa9); /* 38 */
        c = MD5.HH(c, d, a, b, x[7], 16, 0xf6bb4b60); /* 39 */
        b = MD5.HH(b, c, d, a, x[10], 23, 0xbebfbc70); /* 40 */
        a = MD5.HH(a, b, c, d, x[13], 4, 0x289b7ec6); /* 41 */
        d = MD5.HH(d, a, b, c, x[0], 11, 0xeaa127fa); /* 42 */
        c = MD5.HH(c, d, a, b, x[3], 16, 0xd4ef3085); /* 43 */
        b = MD5.HH(b, c, d, a, x[6], 23, 0x04881d05); /* 44 */
        a = MD5.HH(a, b, c, d, x[9], 4, 0xd9d4d039); /* 45 */
        d = MD5.HH(d, a, b, c, x[12], 11, 0xe6db99e5); /* 46 */
        c = MD5.HH(c, d, a, b, x[15], 16, 0x1fa27cf8); /* 47 */
        b = MD5.HH(b, c, d, a, x[2], 23, 0xc4ac5665); /* 48 */

        /* Round 4 */
        a = MD5.II(a, b, c, d, x[0], 6, 0xf4292244); /* 49 */
        d = MD5.II(d, a, b, c, x[7], 10, 0x432aff97); /* 50 */
        c = MD5.II(c, d, a, b, x[14], 15, 0xab9423a7); /* 51 */
        b = MD5.II(b, c, d, a, x[5], 21, 0xfc93a039); /* 52 */
        a = MD5.II(a, b, c, d, x[12], 6, 0x655b59c3); /* 53 */
        d = MD5.II(d, a, b, c, x[3], 10, 0x8f0ccc92); /* 54 */
        c = MD5.II(c, d, a, b, x[10], 15, 0xffeff47d); /* 55 */
        b = MD5.II(b, c, d, a, x[1], 21, 0x85845dd1); /* 56 */
        a = MD5.II(a, b, c, d, x[8], 6, 0x6fa87e4f); /* 57 */
        d = MD5.II(d, a, b, c, x[15], 10, 0xfe2ce6e0); /* 58 */
        c = MD5.II(c, d, a, b, x[6], 15, 0xa3014314); /* 59 */
        b = MD5.II(b, c, d, a, x[13], 21, 0x4e0811a1); /* 60 */
        a = MD5.II(a, b, c, d, x[4], 6, 0xf7537e82); /* 61 */
        d = MD5.II(d, a, b, c, x[11], 10, 0xbd3af235); /* 62 */
        c = MD5.II(c, d, a, b, x[2], 15, 0x2ad7d2bb); /* 63 */
        b = MD5.II(b, c, d, a, x[9], 21, 0xeb86d391); /* 64 */

        this.state[0] = (this.state[0] + a) >>> 0;
        this.state[1] = (this.state[1] + b) >>> 0;
        this.state[2] = (this.state[2] + c) >>> 0;
        this.state[3] = (this.state[3] + d) >>> 0;
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

        const inputlen = inputBytes.length;
        let i = 0;
        let index = (this.count[0] >>> 3) & 0x3F;
        let partlen = 64 - index;

        // Update number of bits
        let addedBits = inputlen << 3;
        this.count[0] += addedBits;
        if (this.count[0] < addedBits) { // overflow
            this.count[1]++;
        }
        this.count[1] += inputlen >>> 29;

        if (inputlen >= partlen) {
            this.buffer.set(inputBytes.subarray(0, partlen), index);
            this.transform(this.buffer);

            for (i = partlen; i + 64 <= inputlen; i += 64) {
                this.transform(inputBytes.subarray(i, i + 64));
            }
            index = 0;
        } else {
            i = 0;
        }

        this.buffer.set(inputBytes.subarray(i), index);
    }

    finish() {
        const digest = new Uint8Array(16);
        let index = (this.count[0] >>> 3) & 0x3F;
        let padlen = (index < 56) ? (56 - index) : (120 - index);

        const PADDING = new Uint8Array(64);
        PADDING[0] = 0x80;

        // Encode bit count (count is bits)
        // count[0] is low 32 bits, count[1] is high 32 bits
        const bits = new Uint8Array(8);
        for (let i = 0; i < 4; i++) {
            bits[i] = (this.count[0] >>> (i * 8)) & 0xFF;
            bits[i + 4] = (this.count[1] >>> (i * 8)) & 0xFF;
        }

        this.update(PADDING.subarray(0, padlen));
        this.update(bits); // Update with 8 bytes of size

        // Encode state
        for (let i = 0; i < 4; i++) {
            let val = this.state[i];
            digest[i * 4] = val & 0xFF;
            digest[i * 4 + 1] = (val >>> 8) & 0xFF;
            digest[i * 4 + 2] = (val >>> 16) & 0xFF;
            digest[i * 4 + 3] = (val >>> 24) & 0xFF;
        }

        return digest;
    }
}

module.exports = MD5;
