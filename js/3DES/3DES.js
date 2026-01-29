
// 3DES.js
// Ported from C implementation and reused DES logic

// ---------------------------------------------------------------------------
// Tables (Standard FIPS 46-3) - Same as DES
// ---------------------------------------------------------------------------

const IP = [
    58, 50, 42, 34, 26, 18, 10, 2,
    60, 52, 44, 36, 28, 20, 12, 4,
    62, 54, 46, 38, 30, 22, 14, 6,
    64, 56, 48, 40, 32, 24, 16, 8,
    57, 49, 41, 33, 25, 17,  9, 1,
    59, 51, 43, 35, 27, 19, 11, 3,
    61, 53, 45, 37, 29, 21, 13, 5,
    63, 55, 47, 39, 31, 23, 15, 7
];

const IP_INV = [
    40, 8, 48, 16, 56, 24, 64, 32,
    39, 7, 47, 15, 55, 23, 63, 31,
    38, 6, 46, 14, 54, 22, 62, 30,
    37, 5, 45, 13, 53, 21, 61, 29,
    36, 4, 44, 12, 52, 20, 60, 28,
    35, 3, 43, 11, 51, 19, 59, 27,
    34, 2, 42, 10, 50, 18, 58, 26,
    33, 1, 41,  9, 49, 17, 57, 25
];

const E = [
    32,  1,  2,  3,  4,  5,
     4,  5,  6,  7,  8,  9,
     8,  9, 10, 11, 12, 13,
    12, 13, 14, 15, 16, 17,
    16, 17, 18, 19, 20, 21,
    20, 21, 22, 23, 24, 25,
    24, 25, 26, 27, 28, 29,
    28, 29, 30, 31, 32,  1
];

const P = [
    16,  7, 20, 21,
    29, 12, 28, 17,
     1, 15, 23, 26,
     5, 18, 31, 10,
     2,  8, 24, 14,
    32, 27,  3,  9,
    19, 13, 30,  6,
    22, 11,  4, 25
];

const PC1 = [
    57, 49, 41, 33, 25, 17,  9,
     1, 58, 50, 42, 34, 26, 18,
    10,  2, 59, 51, 43, 35, 27,
    19, 11,  3, 60, 52, 44, 36,
    63, 55, 47, 39, 31, 23, 15,
     7, 62, 54, 46, 38, 30, 22,
    14,  6, 61, 53, 45, 37, 29,
    21, 13,  5, 28, 20, 12,  4
];

const PC2 = [
    14, 17, 11, 24,  1,  5,
     3, 28, 15,  6, 21, 10,
    23, 19, 12,  4, 26,  8,
    16,  7, 27, 20, 13,  2,
    41, 52, 31, 37, 47, 55,
    30, 40, 51, 45, 33, 48,
    44, 49, 39, 56, 34, 53,
    46, 42, 50, 36, 29, 32
];

const SHIFTS = [
    1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
];

const S_BOX = [
    // S1
    [
        [14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7],
        [0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8],
        [4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0],
        [15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13]
    ],
    // S2
    [
        [15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10],
        [3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5],
        [0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15],
        [13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9]
    ],
    // S3
    [
        [10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8],
        [13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1],
        [13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7],
        [1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12]
    ],
    // S4
    [
        [7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15],
        [13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9],
        [10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4],
        [3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14]
    ],
    // S5
    [
        [2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9],
        [14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6],
        [4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14],
        [11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3]
    ],
    // S6
    [
        [12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11],
        [10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8],
        [9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6],
        [4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13]
    ],
    // S7
    [
        [4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1],
        [13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6],
        [1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2],
        [6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12]
    ],
    // S8
    [
        [13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7],
        [1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2],
        [7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8],
        [2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11]
    ]
];

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

function bytesToBigInt(buf, offset) {
    let val = 0n;
    for (let i = 0; i < 8; ++i) {
        val = (val << 8n) | BigInt(buf[offset + i]);
    }
    return val;
}

function bigIntToBytes(val, buf, offset) {
    for (let i = 7; i >= 0; --i) {
        buf[offset + i] = Number(val & 0xFFn);
        val >>= 8n;
    }
}

// Permute using BigInt
function permute(input, table, n) {
    let result = 0n;
    for (let i = 0; i < n; i++) {
        const pos = table[i];
        const shift = 64n - BigInt(pos);
        if ((input >> shift) & 1n) {
            result |= (1n << (64n - 1n - BigInt(i)));
        }
    }
    return result;
}

// Rotate left 28-bit
function rotl28(val, shift) {
    const v = BigInt(val);
    const s = BigInt(shift);
    const mask28 = 0xFFFFFFFn;
    return ((v << s) | (v >> (28n - s))) & mask28;
}

// ---------------------------------------------------------------------------
// Core Logic (Single Key Schedule)
// ---------------------------------------------------------------------------

function des_key_schedule(key, offset, subkeys) {
    // key is Uint8Array
    const k = bytesToBigInt(key, offset);

    // PC1
    const k56 = permute(k, PC1, 56);

    let c = (k56 >> 36n) & 0xFFFFFFFn;
    let d = (k56 >> 8n) & 0xFFFFFFFn;

    for (let i = 0; i < 16; i++) {
        c = rotl28(c, SHIFTS[i]);
        d = rotl28(d, SHIFTS[i]);

        let cd = (c << 28n) | d;
        cd <<= 8n; 

        subkeys[i] = permute(cd, PC2, 48);
    }
}

// Feistel function F(R, K)
function des_f(r, k) {
    const r_u64 = BigInt(r) << 32n;
    const er = permute(r_u64, E, 48);
    
    const x = er ^ k;

    let output = 0;
    for (let i = 0; i < 8; i++) {
        const shift = 64n - 6n * BigInt(i + 1);
        const chunk = Number((x >> shift) & 0x3Fn);

        const row = ((chunk >> 5) & 1) * 2 + (chunk & 1);
        const col = (chunk >> 1) & 0x0F;

        const s_val = S_BOX[i][row][col];
        output = (output << 4) | s_val;
    }

    const out_u64 = BigInt(output) << 32n;
    const p_out = permute(out_u64, P, 32);

    return Number(p_out >> 32n);
}

function des_block_op(block, subkeys, mode) {
    block = permute(block, IP, 64);

    let l = Number(block >> 32n);
    let r = Number(block & 0xFFFFFFFFn);

    for (let i = 0; i < 16; i++) {
        const prev_l = l;
        l = r;

        let k;
        if (mode === 1) { // Encrypt
            k = subkeys[i];
        } else { // Decrypt
            k = subkeys[15 - i];
        }

        r = (prev_l ^ des_f(r, k)) >>> 0; 
    }

    const combined = (BigInt(r) << 32n) | BigInt(l); 
    return permute(combined, IP_INV, 64);
}

// ---------------------------------------------------------------------------
// 3DES Core
// ---------------------------------------------------------------------------

class TDES_ctx {
    constructor() {
        this.subkeys1 = new BigUint64Array(16);
        this.subkeys2 = new BigUint64Array(16);
        this.subkeys3 = new BigUint64Array(16);
        this.iv = 0n;
    }
}

function TDES_init(ctx, key) {
    // Key must be 24 bytes
    des_key_schedule(key, 0, ctx.subkeys1);
    des_key_schedule(key, 8, ctx.subkeys2);
    des_key_schedule(key, 16, ctx.subkeys3);
    ctx.iv = 0n;
}

function TDES_init_iv(ctx, key, iv) {
    TDES_init(ctx, key);
    if (iv) {
        ctx.iv = bytesToBigInt(iv, 0);
    }
}

// EDE Mode: Encrypt(K1) -> Decrypt(K2) -> Encrypt(K3)
function tdes_process_block(ctx, block, mode) {
    if (mode === 1) { // Encrypt
        block = des_block_op(block, ctx.subkeys1, 1);
        block = des_block_op(block, ctx.subkeys2, 0);
        block = des_block_op(block, ctx.subkeys3, 1);
    } else { // Decrypt
        block = des_block_op(block, ctx.subkeys3, 0);
        block = des_block_op(block, ctx.subkeys2, 1);
        block = des_block_op(block, ctx.subkeys1, 0);
    }
    return block;
}

// ---------------------------------------------------------------------------
// Modes
// ---------------------------------------------------------------------------

function TDES_ECB_encrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let block = bytesToBigInt(buf, i);
        block = tdes_process_block(ctx, block, 1);
        bigIntToBytes(block, buf, i);
    }
}

function TDES_ECB_decrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let block = bytesToBigInt(buf, i);
        block = tdes_process_block(ctx, block, 0);
        bigIntToBytes(block, buf, i);
    }
}

function TDES_CBC_encrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let block = bytesToBigInt(buf, i);
        block ^= ctx.iv;
        block = tdes_process_block(ctx, block, 1);
        ctx.iv = block;
        bigIntToBytes(block, buf, i);
    }
}

function TDES_CBC_decrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let block = bytesToBigInt(buf, i);
        let next_iv = block;
        block = tdes_process_block(ctx, block, 0);
        block ^= ctx.iv;
        ctx.iv = next_iv;
        bigIntToBytes(block, buf, i);
    }
}

function TDES_CFB_encrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let iv_enc = tdes_process_block(ctx, ctx.iv, 1);
        let block = bytesToBigInt(buf, i);
        block ^= iv_enc;
        ctx.iv = block;
        bigIntToBytes(block, buf, i);
    }
}

function TDES_CFB_decrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let iv_enc = tdes_process_block(ctx, ctx.iv, 1);
        let block = bytesToBigInt(buf, i);
        let next_iv = block;
        block ^= iv_enc;
        ctx.iv = next_iv;
        bigIntToBytes(block, buf, i);
    }
}

function TDES_OFB_encrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let iv_enc = tdes_process_block(ctx, ctx.iv, 1);
        ctx.iv = iv_enc;
        let block = bytesToBigInt(buf, i);
        block ^= iv_enc;
        bigIntToBytes(block, buf, i);
    }
}

const TDES_OFB_decrypt_buffer = TDES_OFB_encrypt_buffer;

function TDES_CTR_encrypt_buffer(ctx, buf) {
    for (let i = 0; i < buf.length; i += 8) {
        let keystream = tdes_process_block(ctx, ctx.iv, 1);
        ctx.iv = (ctx.iv + 1n) & 0xFFFFFFFFFFFFFFFFn;
        
        let block = bytesToBigInt(buf, i);
        block ^= keystream;
        bigIntToBytes(block, buf, i);
    }
}

const TDES_CTR_decrypt_buffer = TDES_CTR_encrypt_buffer;

module.exports = {
    TDES_ctx,
    TDES_init,
    TDES_init_iv,
    TDES_ECB_encrypt_buffer,
    TDES_ECB_decrypt_buffer,
    TDES_CBC_encrypt_buffer,
    TDES_CBC_decrypt_buffer,
    TDES_CFB_encrypt_buffer,
    TDES_CFB_decrypt_buffer,
    TDES_OFB_encrypt_buffer,
    TDES_OFB_decrypt_buffer,
    TDES_CTR_encrypt_buffer,
    TDES_CTR_decrypt_buffer
};
