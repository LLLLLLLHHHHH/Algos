
// SM3.js
// Ported from c/SM3/SM3.c

class SM3 {
    constructor() {
        this.reset();
    }

    reset() {
        this.total = [0, 0]; // total[0] low, total[1] high (in terms of storage index, but logic is custom)
        // In C: total[0] is low 32 bits (mostly), total[1] is high.
        // C logic: total[0] += ilen; if (total[0] < ilen) total[1]++;
        
        this.state = new Uint32Array(8);
        this.buffer = new Uint8Array(64);
        this.bufferLen = 0; // Tracks current buffer usage (C uses implicit calculation from total[0] & 0x3F)

        this.state[0] = 0x7380166F;
        this.state[1] = 0x4914B2B9;
        this.state[2] = 0x172442D7;
        this.state[3] = 0xDA8A0600;
        this.state[4] = 0xA96F30BC;
        this.state[5] = 0x163138AA;
        this.state[6] = 0xE38DEE4D;
        this.state[7] = 0xB0FB0E4E;
    }

    // 32-bit Rotate Left
    static ROTL(x, n) {
        return ((x << n) | (x >>> (32 - n))) >>> 0;
    }

    static P0(x) {
        return (x ^ SM3.ROTL(x, 9) ^ SM3.ROTL(x, 17)) >>> 0;
    }

    static P1(x) {
        return (x ^ SM3.ROTL(x, 15) ^ SM3.ROTL(x, 23)) >>> 0;
    }

    static FF0(x, y, z) {
        return (x ^ y ^ z) >>> 0;
    }

    static FF1(x, y, z) {
        return ((x & y) | (x & z) | (y & z)) >>> 0;
    }

    static GG0(x, y, z) {
        return (x ^ y ^ z) >>> 0;
    }

    static GG1(x, y, z) {
        return ((x & y) | (~x & z)) >>> 0;
    }

    static GET_ULONG_BE(b, i) {
        return ((b[i] << 24) | (b[i + 1] << 16) | (b[i + 2] << 8) | b[i + 3]) >>> 0;
    }

    static PUT_ULONG_BE(n, b, i) {
        b[i] = (n >>> 24) & 0xFF;
        b[i + 1] = (n >>> 16) & 0xFF;
        b[i + 2] = (n >>> 8) & 0xFF;
        b[i + 3] = n & 0xFF;
    }

    process(data, offset) {
        const W = new Uint32Array(68);
        const W1 = new Uint32Array(64);
        const T = new Uint32Array(64);

        for (let j = 0; j < 16; j++) T[j] = 0x79CC4519;
        for (let j = 16; j < 64; j++) T[j] = 0x7A879D8A;

        for (let j = 0; j < 16; j++) {
            W[j] = SM3.GET_ULONG_BE(data, offset + j * 4);
        }

        for (let j = 16; j < 68; j++) {
            const Temp1 = W[j - 16] ^ W[j - 9];
            const Temp2 = SM3.ROTL(W[j - 3], 15);
            const Temp3 = Temp1 ^ Temp2;
            const Temp4 = SM3.P1(Temp3);
            const Temp5 = SM3.ROTL(W[j - 13], 7) ^ W[j - 6];
            W[j] = (Temp4 ^ Temp5) >>> 0;
        }

        for (let j = 0; j < 64; j++) {
            W1[j] = (W[j] ^ W[j + 4]) >>> 0;
        }

        let A = this.state[0];
        let B = this.state[1];
        let C = this.state[2];
        let D = this.state[3];
        let E = this.state[4];
        let F = this.state[5];
        let G = this.state[6];
        let H = this.state[7];

        // 0 - 15
        for (let j = 0; j < 16; j++) {
            const SS1 = SM3.ROTL((SM3.ROTL(A, 12) + E + SM3.ROTL(T[j], j)) >>> 0, 7);
            const SS2 = (SS1 ^ SM3.ROTL(A, 12)) >>> 0;
            const TT1 = (SM3.FF0(A, B, C) + D + SS2 + W1[j]) >>> 0;
            const TT2 = (SM3.GG0(E, F, G) + H + SS1 + W[j]) >>> 0;
            D = C;
            C = SM3.ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = SM3.ROTL(F, 19);
            F = E;
            E = SM3.P0(TT2);
        }

        // 16 - 63
        for (let j = 16; j < 64; j++) {
            const SS1 = SM3.ROTL((SM3.ROTL(A, 12) + E + SM3.ROTL(T[j], j)) >>> 0, 7);
            const SS2 = (SS1 ^ SM3.ROTL(A, 12)) >>> 0;
            const TT1 = (SM3.FF1(A, B, C) + D + SS2 + W1[j]) >>> 0;
            const TT2 = (SM3.GG1(E, F, G) + H + SS1 + W[j]) >>> 0;
            D = C;
            C = SM3.ROTL(B, 9);
            B = A;
            A = TT1;
            H = G;
            G = SM3.ROTL(F, 19);
            F = E;
            E = SM3.P0(TT2);
        }

        this.state[0] = (this.state[0] ^ A) >>> 0;
        this.state[1] = (this.state[1] ^ B) >>> 0;
        this.state[2] = (this.state[2] ^ C) >>> 0;
        this.state[3] = (this.state[3] ^ D) >>> 0;
        this.state[4] = (this.state[4] ^ E) >>> 0;
        this.state[5] = (this.state[5] ^ F) >>> 0;
        this.state[6] = (this.state[6] ^ G) >>> 0;
        this.state[7] = (this.state[7] ^ H) >>> 0;
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

        const ilen = inputBytes.length;
        let left = this.total[0] & 0x3F;
        let fill = 64 - left;

        this.total[0] += ilen;
        if (this.total[0] < ilen) { // Overflow check (although total[0] is treated as number in JS, precision limit is 2^53)
            // In C, total[0] is uint32_t. Here we should simulate 32-bit wrapping manually if we want exact C behavior,
            // but JS numbers are doubles. Let's strictly follow C logic using >>> 0.
        }
        
        // Correct 64-bit counter logic using two 32-bit integers
        const oldTotal0 = (this.total[0] - ilen) >>> 0; // Restore old value if we assumed total[0] was just updated
        // Actually, let's just use total[0] and total[1] as 32-bit integers
        // Revert the += ilen above, let's do it properly
        this.total[0] = (this.total[0] - ilen); // JS double precision allows this if small enough, but let's reset logic.
        
        // Proper update logic
        const old_total_0 = this.total[0];
        this.total[0] = (this.total[0] + ilen) >>> 0;
        if (this.total[0] < old_total_0) {
            this.total[1] = (this.total[1] + 1) >>> 0;
        }
        
        // Also add carry from large ilen if ilen > 2^32 (unlikely in this context but correct for completeness)
        // C code: ctx->total[1] += (ilen >> 32) -- input ilen is int (32-bit), so no need.

        let inputIdx = 0;
        let remainingLen = ilen;

        if (left && remainingLen >= fill) {
            this.buffer.set(inputBytes.subarray(0, fill), left);
            this.process(this.buffer, 0);
            inputIdx += fill;
            remainingLen -= fill;
            left = 0;
        }

        while (remainingLen >= 64) {
            this.process(inputBytes, inputIdx);
            inputIdx += 64;
            remainingLen -= 64;
        }

        if (remainingLen > 0) {
            this.buffer.set(inputBytes.subarray(inputIdx, inputIdx + remainingLen), left);
        }
    }

    finish() {
        const high = (this.total[0] >>> 29) | (this.total[1] << 3);
        const low = (this.total[0] << 3);
        
        const msglen = new Uint8Array(8);
        SM3.PUT_ULONG_BE(high >>> 0, msglen, 0);
        SM3.PUT_ULONG_BE(low >>> 0, msglen, 4);

        const last = this.total[0] & 0x3F;
        const padn = (last < 56) ? (56 - last) : (120 - last);

        const PADDING = new Uint8Array(64);
        PADDING[0] = 0x80;

        this.update(PADDING.subarray(0, padn));
        this.update(msglen);

        const output = new Uint8Array(32);
        for (let i = 0; i < 8; i++) {
            SM3.PUT_ULONG_BE(this.state[i], output, i * 4);
        }

        return output;
    }
}

module.exports = SM3;
