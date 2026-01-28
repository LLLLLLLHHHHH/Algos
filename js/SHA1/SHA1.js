
// SHA1.js
// Ported from c/SHA1/SHA1.c

class SHA1 {
    constructor() {
        this.reset();
    }

    reset() {
        this.state = new Uint32Array(5);
        this.state[0] = 0x67452301;
        this.state[1] = 0xEFCDAB89;
        this.state[2] = 0x98BADCFE;
        this.state[3] = 0x10325476;
        this.state[4] = 0xC3D2E1F0;

        this.count = [0, 0]; // count[0] low, count[1] high (bits)
        this.buffer = new Uint8Array(64);
    }

    static rol(value, bits) {
        return ((value << bits) | (value >>> (32 - bits))) >>> 0;
    }

    static get_uint32_be(b, i) {
        return ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
    }

    static put_uint32_be(n, b, i) {
        b[i] = (n >>> 24) & 0xFF;
        b[i + 1] = (n >>> 16) & 0xFF;
        b[i + 2] = (n >>> 8) & 0xFF;
        b[i + 3] = n & 0xFF;
    }

    transform(buffer) {
        let a, b, c, d, e;
        const w = new Uint32Array(80);
        let i;

        for (i = 0; i < 16; i++) {
            w[i] = SHA1.get_uint32_be(buffer, i * 4);
        }
        for (i = 16; i < 80; i++) {
            w[i] = SHA1.rol(w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16], 1);
        }

        a = this.state[0];
        b = this.state[1];
        c = this.state[2];
        d = this.state[3];
        e = this.state[4];

        for (i = 0; i < 20; i++) {
            const temp = (SHA1.rol(a, 5) + ((b & c) | (~b & d)) + e + 0x5A827999 + w[i]) >>> 0;
            e = d;
            d = c;
            c = SHA1.rol(b, 30);
            b = a;
            a = temp;
        }

        for (i = 20; i < 40; i++) {
            const temp = (SHA1.rol(a, 5) + (b ^ c ^ d) + e + 0x6ED9EBA1 + w[i]) >>> 0;
            e = d;
            d = c;
            c = SHA1.rol(b, 30);
            b = a;
            a = temp;
        }

        for (i = 40; i < 60; i++) {
            const temp = (SHA1.rol(a, 5) + ((b & c) | (b & d) | (c & d)) + e + 0x8F1BBCDC + w[i]) >>> 0;
            e = d;
            d = c;
            c = SHA1.rol(b, 30);
            b = a;
            a = temp;
        }

        for (i = 60; i < 80; i++) {
            const temp = (SHA1.rol(a, 5) + (b ^ c ^ d) + e + 0xCA62C1D6 + w[i]) >>> 0;
            e = d;
            d = c;
            c = SHA1.rol(b, 30);
            b = a;
            a = temp;
        }

        this.state[0] = (this.state[0] + a) >>> 0;
        this.state[1] = (this.state[1] + b) >>> 0;
        this.state[2] = (this.state[2] + c) >>> 0;
        this.state[3] = (this.state[3] + d) >>> 0;
        this.state[4] = (this.state[4] + e) >>> 0;
    }

    update(data) {
        let input;
        if (typeof data === 'string') {
            input = new TextEncoder().encode(data);
        } else {
            input = new Uint8Array(data);
        }
        
        const len = input.length;
        let j = (this.count[0] >>> 3) & 63;
        
        // Update bit count
        const old_count0 = this.count[0];
        this.count[0] = (this.count[0] + (len << 3)) >>> 0;
        if (this.count[0] < old_count0) {
            this.count[1]++;
        }
        this.count[1] = (this.count[1] + (len >>> 29)) >>> 0;

        let i = 0;
        if ((j + len) > 63) {
            i = 64 - j;
            this.buffer.set(input.subarray(0, i), j);
            this.transform(this.buffer);
            
            for (; i + 63 < len; i += 64) {
                this.transform(input.subarray(i, i + 64));
            }
            j = 0;
        }
        
        this.buffer.set(input.subarray(i, len), j);
    }

    final() {
        const digest = new Uint8Array(20);
        const finalcount = new Uint8Array(8);

        SHA1.put_uint32_be(this.count[1], finalcount, 0);
        SHA1.put_uint32_be(this.count[0], finalcount, 4);

        let i = (this.count[0] >>> 3) & 63;

        this.buffer[i++] = 0x80;

        if (i > 56) {
            while (i < 64) {
                this.buffer[i++] = 0;
            }
            this.transform(this.buffer);
            i = 0;
        }

        while (i < 56) {
            this.buffer[i++] = 0;
        }

        this.buffer.set(finalcount, 56);
        this.transform(this.buffer);

        for (i = 0; i < 5; i++) {
            SHA1.put_uint32_be(this.state[i], digest, i * 4);
        }

        return digest;
    }
}

module.exports = SHA1;
