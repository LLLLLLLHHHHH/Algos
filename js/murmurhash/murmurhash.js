
// murmurhash.js
// Ported from c/murmurhash/murmurhash.c

/**
 * MurmurHash3 32-bit implementation
 * 
 * @param {string|Uint8Array} key - The input data
 * @param {number} [seed=0] - The seed value
 * @returns {number} - The 32-bit hash value
 */
function murmurhash(key, seed = 0) {
    let keyBytes;
    if (typeof key === 'string') {
        keyBytes = new Uint8Array(key.length);
        for (let i = 0; i < key.length; i++) {
            keyBytes[i] = key.charCodeAt(i);
        }
    } else {
        keyBytes = key;
    }
    
    const len = keyBytes.length;
    let h = seed >>> 0; // Ensure 32-bit unsigned
    
    const c1 = 0xcc9e2d51;
    const c2 = 0x1b873593;
    const r1 = 15;
    const r2 = 13;
    const m = 5;
    const n = 0xe6546b64;
    
    // Process 4-byte chunks
    const l = Math.floor(len / 4);
    
    // In C implementation:
    // chunks = (const uint32_t *)(d + l * 4);
    // for (i = -l; i != 0; ++i) { ... chunks[i] ... }
    // This iterates from the start (d + 0) up to the last full chunk.
    // chunks[i] where chunks is at end and i is negative means it accesses
    // memory before chunks pointer. effectively d[0..4], d[4..8], etc.
    
    // JS DataView or manual read
    for (let i = 0; i < l; i++) {
        // Read 32-bit integer little-endian (implied by htole32 on little-endian machine)
        // C code: k = chunks[i];
        // Note: The C loop `for (i = -l; i != 0; ++i)` with `chunks` pointing to END
        // means `chunks[-l]` is the first block.
        
        const idx = i * 4;
        let k = (keyBytes[idx] & 0xff) |
                ((keyBytes[idx + 1] & 0xff) << 8) |
                ((keyBytes[idx + 2] & 0xff) << 16) |
                ((keyBytes[idx + 3] & 0xff) << 24);
        
        k = Math.imul(k, c1);
        k = (k << r1) | (k >>> (32 - r1));
        k = Math.imul(k, c2);
        
        h ^= k;
        h = (h << r2) | (h >>> (32 - r2));
        h = Math.imul(h, m) + n;
        h = h >>> 0; // Ensure 32-bit unsigned
    }
    
    // Process remaining bytes
    let k = 0;
    const tailIdx = l * 4;
    const rem = len & 3;
    
    // In C: switch(len & 3) case 3: k^=... case 2: ... case 1: ...
    // Note C switch fallthrough!
    // case 3: k ^= (tail[2] << 16);
    // case 2: k ^= (tail[1] << 8);
    // case 1: k ^= tail[0];
    
    // JS Logic:
    if (rem >= 3) k ^= (keyBytes[tailIdx + 2] & 0xff) << 16;
    if (rem >= 2) k ^= (keyBytes[tailIdx + 1] & 0xff) << 8;
    if (rem >= 1) {
        k ^= (keyBytes[tailIdx] & 0xff);
        k = Math.imul(k, c1);
        k = (k << r1) | (k >>> (32 - r1));
        k = Math.imul(k, c2);
        h ^= k;
        h = h >>> 0;
    }
    
    // Finalization
    h ^= len;
    h = h >>> 0;
    
    h ^= (h >>> 16);
    h = Math.imul(h, 0x85ebca6b);
    h = h >>> 0;
    
    h ^= (h >>> 13);
    h = Math.imul(h, 0xc2b2ae35);
    h = h >>> 0;
    
    h ^= (h >>> 16);
    h = h >>> 0;
    
    return h;
}

module.exports = murmurhash;
