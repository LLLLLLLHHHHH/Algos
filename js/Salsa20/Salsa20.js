
// Salsa20.js
// Ported from c/Salsa20/salsa20.c

class Salsa20 {
    constructor(key, nonce) {
        this.state = new Uint32Array(16);
        this.init(key, nonce);
    }

    static ROTL(a, b) {
        return ((a << b) | (a >>> (32 - b))) >>> 0;
    }

    static load32_le(src, offset) {
        return (src[offset] |
               (src[offset + 1] << 8) |
               (src[offset + 2] << 16) |
               (src[offset + 3] << 24)) >>> 0;
    }

    static store32_le(dst, offset, val) {
        dst[offset] = val & 0xFF;
        dst[offset + 1] = (val >>> 8) & 0xFF;
        dst[offset + 2] = (val >>> 16) & 0xFF;
        dst[offset + 3] = (val >>> 24) & 0xFF;
    }

    init(key, nonce) {
        // Constants "expand 32-byte k"
        const constant = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574];
        
        this.state[0] = constant[0];
        this.state[5] = constant[1];
        this.state[10] = constant[2];
        this.state[15] = constant[3];

        // Key
        this.state[1] = Salsa20.load32_le(key, 0);
        this.state[2] = Salsa20.load32_le(key, 4);
        this.state[3] = Salsa20.load32_le(key, 8);
        this.state[4] = Salsa20.load32_le(key, 12);
        this.state[11] = Salsa20.load32_le(key, 16);
        this.state[12] = Salsa20.load32_le(key, 20);
        this.state[13] = Salsa20.load32_le(key, 24);
        this.state[14] = Salsa20.load32_le(key, 28);

        // Nonce
        this.state[6] = Salsa20.load32_le(nonce, 0);
        this.state[7] = Salsa20.load32_le(nonce, 4);

        // Block counter (64-bit), starts at 0
        this.state[8] = 0;
        this.state[9] = 0;
    }

    block(output) {
        const x = new Uint32Array(this.state);

        for (let i = 0; i < 10; i++) {
            // Column rounds
            this.QR(x, 0, 4, 8, 12);
            this.QR(x, 5, 9, 13, 1);
            this.QR(x, 10, 14, 2, 6);
            this.QR(x, 15, 3, 7, 11);

            // Row rounds
            this.QR(x, 0, 1, 2, 3);
            this.QR(x, 5, 6, 7, 4);
            this.QR(x, 10, 11, 8, 9);
            this.QR(x, 15, 12, 13, 14);
        }

        for (let i = 0; i < 16; i++) {
            x[i] = (x[i] + this.state[i]) >>> 0;
            Salsa20.store32_le(output, i * 4, x[i]);
        }
    }

    QR(x, a, b, c, d) {
        x[b] ^= Salsa20.ROTL((x[a] + x[d]) >>> 0, 7);
        x[c] ^= Salsa20.ROTL((x[b] + x[a]) >>> 0, 9);
        x[d] ^= Salsa20.ROTL((x[c] + x[b]) >>> 0, 13);
        x[a] ^= Salsa20.ROTL((x[d] + x[c]) >>> 0, 18);
    }

    crypt(input) {
        let inputBytes;
        if (typeof input === 'string') {
            inputBytes = new TextEncoder().encode(input);
        } else {
            inputBytes = input;
        }

        const len = inputBytes.length;
        const output = new Uint8Array(len);
        const blockBuffer = new Uint8Array(64);
        let i = 0;
        let remaining = len;

        while (remaining > 0) {
            this.block(blockBuffer);

            // Increment 64-bit counter
            this.state[8] = (this.state[8] + 1) >>> 0;
            if (this.state[8] === 0) {
                this.state[9] = (this.state[9] + 1) >>> 0;
            }

            const n = (remaining < 64) ? remaining : 64;
            for (let j = 0; j < n; j++) {
                output[i + j] = inputBytes[i + j] ^ blockBuffer[j];
            }

            i += n;
            remaining -= n;
        }

        return output;
    }
}

module.exports = Salsa20;
