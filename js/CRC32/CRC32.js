// IEEE 802.3 CRC-32 Polynomial: 0xEDB88320 (Reflected)
const CRC32_POLY = 0xEDB88320;

let crc32_table = null;

function crc32_init() {
    if (crc32_table !== null) return;

    crc32_table = new Uint32Array(256);
    for (let i = 0; i < 256; i++) {
        let crc = i;
        for (let j = 0; j < 8; j++) {
            if (crc & 1) {
                crc = (crc >>> 1) ^ CRC32_POLY;
            } else {
                crc = crc >>> 1;
            }
        }
        crc32_table[i] = (crc >>> 0); // Ensure unsigned 32-bit
    }
}

/**
 * Calculate CRC32
 * @param {number} crc - Initial value (usually 0xFFFFFFFF or result from previous call)
 * @param {Uint8Array|string} buf - Data buffer or string
 * @returns {number} - The updated CRC register value (not inverted yet)
 */
function crc32(crc, buf) {
    if (crc32_table === null) {
        crc32_init();
    }

    if (typeof buf === 'string') {
        buf = new TextEncoder().encode(buf);
    }

    // Ensure crc is unsigned 32-bit
    crc = crc >>> 0;

    for (let i = 0; i < buf.length; i++) {
        const tableIndex = (crc ^ buf[i]) & 0xFF;
        crc = (crc >>> 8) ^ crc32_table[tableIndex];
    }

    return (crc >>> 0);
}

/**
 * Calculate total CRC32 (Standard implementation)
 * @param {Uint8Array|string} buf - Data buffer
 * @returns {number} - The final inverted CRC32 value
 */
function crc32_total(buf) {
    let crc = 0xFFFFFFFF;
    crc = crc32(crc, buf);
    return (crc ^ 0xFFFFFFFF) >>> 0;
}

module.exports = {
    crc32_init,
    crc32,
    crc32_total
};
