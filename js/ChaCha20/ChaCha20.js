
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

    static hchacha20(key, nonce16) {
        // draft-arciszewski-xchacha-03, Section 2.2
        const st = new Uint32Array(16);
        // Constants "expand 32-byte k"
        st[0] = 0x61707865; st[1] = 0x3320646e; st[2] = 0x79622d32; st[3] = 0x6b206574;
        // Key
        for (let i = 0; i < 8; i++) st[4 + i] = ChaCha20.load32_le(key, i * 4);
        // 128-bit nonce in last 4 words
        for (let i = 0; i < 4; i++) st[12 + i] = ChaCha20.load32_le(nonce16, i * 4);

        const x = new Uint32Array(st);
        for (let i = 0; i < 10; i++) {
            // Column rounds
            ChaCha20.QRstatic(x, 0, 4, 8, 12);
            ChaCha20.QRstatic(x, 1, 5, 9, 13);
            ChaCha20.QRstatic(x, 2, 6, 10, 14);
            ChaCha20.QRstatic(x, 3, 7, 11, 15);
            // Diagonal rounds
            ChaCha20.QRstatic(x, 0, 5, 10, 15);
            ChaCha20.QRstatic(x, 1, 6, 11, 12);
            ChaCha20.QRstatic(x, 2, 7, 8, 13);
            ChaCha20.QRstatic(x, 3, 4, 9, 14);
        }

        // Output: words 0..3 and 12..15, little-endian
        const out = new Uint8Array(32);
        for (let i = 0; i < 4; i++) ChaCha20.store32_le(out, i * 4, x[i]);
        for (let i = 0; i < 4; i++) ChaCha20.store32_le(out, (4 + i) * 4, x[12 + i]);
        return out;
    }

    static QRstatic(x, a, b, c, d) {
        x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = ChaCha20.ROTL(x[d], 16);
        x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = ChaCha20.ROTL(x[b], 12);
        x[a] = (x[a] + x[b]) >>> 0; x[d] ^= x[a]; x[d] = ChaCha20.ROTL(x[d], 8);
        x[c] = (x[c] + x[d]) >>> 0; x[b] ^= x[c]; x[b] = ChaCha20.ROTL(x[b], 7);
    }

    init(key, nonce, counter) {
        // Constants "expand 32-byte k"
        const constant = [0x61707865, 0x3320646e, 0x79622d32, 0x6b206574]; // Little Endian integers
        
        this.state[0] = constant[0];
        this.state[1] = constant[1];
        this.state[2] = constant[2];
        this.state[3] = constant[3];

        // Support:
        // - ChaCha20 (RFC7539): 12-byte nonce
        // - XChaCha20: 24-byte (192-bit) nonce via HChaCha20 subkey derivation
        let realKey = key;
        let realNonce = nonce;
        if (nonce.length === 24) {
            const subkey = ChaCha20.hchacha20(key, nonce.subarray(0, 16));
            const nonce12 = new Uint8Array(12);
            // nonce12 = 0x00000000 || nonce[16..23]
            nonce12.set(nonce.subarray(16, 24), 4);
            realKey = subkey;
            realNonce = nonce12;
        }

        // Key (always 32 bytes)
        for (let i = 0; i < 8; i++) {
            this.state[4 + i] = ChaCha20.load32_le(realKey, i * 4);
        }

        // Counter
        this.state[12] = counter;

        // Nonce
        for (let i = 0; i < 3; i++) {
            this.state[13 + i] = ChaCha20.load32_le(realNonce, i * 4);
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
