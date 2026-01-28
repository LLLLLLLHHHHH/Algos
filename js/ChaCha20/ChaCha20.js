
// ChaCha20.js
// Ported from c/ChaCha20/chacha20.c

class ChaCha20 {
    constructor(key, nonce, counter = 1) {
        this.state = new Uint32Array(16);
        this.init(key, nonce, counter);
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

    init(key, nonce, counter) {
        // Constants "expand 32-byte k"
        const constant = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // Little Endian integers
        
        this.state[0] = constant[0];
        this.state[1] = constant[1];
        this.state[2] = constant[2];
        this.state[3] = constant[3];

        // Key
        for (let i = 0; i < 8; i++) {
            this.state[4 + i] = ChaCha20.load32_le(key, i * 4);
        }

        // Counter
        this.state[12] = counter;

        // Nonce
        for (let i = 0; i < 3; i++) {
            this.state[13 + i] = ChaCha20.load32_le(nonce, i * 4);
        }
    }

    block(output) {
        const x = new Uint32Array(this.state);

        for (let i = 0; i < 10; i++) {
            // Column rounds
            this.QR(x, 0, 4, 8, 12);
            this.QR(x, 1, 5, 9, 13);
            this.QR(x, 2, 6, 10, 14);
            this.QR(x, 3, 7, 11, 15);
            
            // Diagonal rounds
            this.QR(x, 0, 5, 10, 15);
            this.QR(x, 1, 6, 11, 12);
            this.QR(x, 2, 7, 8, 13);
            this.QR(x, 3, 4, 9, 14);
        }

        for (let i = 0; i < 16; i++) {
            x[i] = (x[i] + this.state[i]) >>> 0;
            ChaCha20.store32_le(output, i * 4, x[i]);
        }
    }

    QR(x, a, b, c, d) {
        x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = ChaCha20.ROTL(x[d], 16);
        x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = ChaCha20.ROTL(x[b], 12);
        x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = ChaCha20.ROTL(x[d], 8);
        x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = ChaCha20.ROTL(x[b], 7);
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
            
            // Increment counter
            this.state[12] = (this.state[12] + 1) >>> 0;

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

module.exports = ChaCha20;
