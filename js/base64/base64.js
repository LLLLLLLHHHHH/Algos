
// base64.js
// Ported from c/base64/base64.c

const PADDING = '='.charCodeAt(0);

const en_table = [
    'A', 'B', 'C', 'D', 'E', 'F', 'G', 'H',
    'I', 'J', 'K', 'L', 'M', 'N', 'O', 'P',
    'Q', 'R', 'S', 'T', 'U', 'V', 'W', 'X',
    'Y', 'Z', 'a', 'b', 'c', 'd', 'e', 'f',
    'g', 'h', 'i', 'j', 'k', 'l', 'm', 'n',
    'o', 'p', 'q', 'r', 's', 't', 'u', 'v',
    'w', 'x', 'y', 'z', '0', '1', '2', '3',
    '4', '5', '6', '7', '8', '9', '+', '/'
];

const de_table = [
    /* nul, soh, stx, etx, eot, enq, ack, bel, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /*  bs,  ht,  nl,  vt,  np,  cr,  so,  si, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /* dle, dc1, dc2, dc3, dc4, nak, syn, etb, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /* can,  em, sub, esc,  fs,  gs,  rs,  us, */
    255, 255, 255, 255, 255, 255, 255, 255,

    /*  sp, '!', '"', '#', '$', '%', '&', ''', */
    255, 255, 255, 255, 255, 255, 255, 255,

    /* '(', ')', '*', '+', ',', '-', '.', '/', */
    255, 255, 255,  62, 255, 255, 255,  63,

    /* '0', '1', '2', '3', '4', '5', '6', '7', */
    52,  53,  54,  55,  56,  57,  58,  59,

    /* '8', '9', ':', ';', '<', '=', '>', '?', */
    60,  61, 255, 255, 255, 255, 255, 255,

    /* '@', 'A', 'B', 'C', 'D', 'E', 'F', 'G', */
    255,   0,   1,  2,   3,   4,   5,    6,

    /* 'H', 'I', 'J', 'K', 'L', 'M', 'N', 'O', */
            7,   8,   9,  10,  11,  12,  13,  14,

    /* 'P', 'Q', 'R', 'S', 'T', 'U', 'V', 'W', */
        15,  16,  17,  18,  19,  20,  21,  22,

    /* 'X', 'Y', 'Z', '[', '\', ']', '^', '_', */
        23,  24,  25, 255, 255, 255, 255, 255,

    /* '`', 'a', 'b', 'c', 'd', 'e', 'f', 'g', */
        255,  26,  27,  28,  29,  30,  31,  32,

    /* 'h', 'i', 'j', 'k', 'l', 'm', 'n', 'o', */
        33,  34,  35,  36,  37,  38,  39,  40,

    /* 'p', 'q', 'r', 's', 't', 'u', 'v', 'w', */
        41,  42,  43,  44,  45,  46,  47,  48,

    /* 'x', 'y', 'z', '{', '|', '}', '~', del, */
        49,  50,  51, 255, 255, 255, 255, 255
];

function base64_encode(in_data) {
    let len;
    let bytes;

    if (typeof in_data === 'string') {
        len = in_data.length;
        bytes = new Uint8Array(len);
        for (let k = 0; k < len; k++) {
            bytes[k] = in_data.charCodeAt(k);
        }
    } else {
        bytes = in_data;
        len = bytes.length;
    }

    let out = [];
    let state = 0;
    let last = 0;
    let i, j;

    for (i = 0, j = 0; i < len; i++) {
        let c = bytes[i];

        switch (state) {
            case 0:
                state = 1;
                out.push(en_table[(c >> 2) & 0x3f]);
                j++;
                break;
            
            case 1:
                state = 2;
                out.push(en_table[((last & 0x3) << 4) | ((c >> 4) & 0xf)]);
                j++;
                break;

            case 2:
                state = 0;
                out.push(en_table[((last & 0xf) << 2) | ((c >> 6) & 0x3)]);
                j++;
                out.push(en_table[c & 0x3f]);
                j++;
                break;
        }
        last = c;
    }

    switch (state) {
        case 1:
            out.push(en_table[(last & 0x3) << 4]);
            j++;
            out.push(String.fromCharCode(PADDING));
            j++;
            out.push(String.fromCharCode(PADDING));
            j++;
            break;
        
        case 2:
            out.push(en_table[(last & 0xf) << 2]);
            j++;
            out.push(String.fromCharCode(PADDING));
            j++;
            break;
    }

    return out.join('');
}

function base64_decode(in_str) {
    let len = in_str.length;
    if (len % 4 !== 0) return null; // Or return empty Uint8Array? C returns 0 length.

    let out = []; // Dynamic array, will convert to Uint8Array at end
    let state = 0;
    let i, j;

    for (i = 0, j = 0; i < len; ++i) {
        if (in_str.charCodeAt(i) === PADDING) break;
        
        let charCode = in_str.charCodeAt(i);
        // Handle out of bounds for de_table if necessary, but assuming valid input range [0, 127] roughly
        // If charCode >= 128, undefined behavior in C code (array access out of bounds or garbage). 
        // We'll just assume it maps to 255 if undefined in JS or check bounds.
        let c = (charCode < de_table.length) ? de_table[charCode] : 255;
        
        if (c === 255) {
            // Invalid character or ignored? 
            // C code doesn't explicitly handle invalid chars other than mapping to 255.
            // If 255, logic below continues.
        }

        switch (i & 0x3) { // % 4
            case 0:
                // out[j] = (c << 2) & 0xff;
                out[j] = (c << 2) & 0xff;
                break;
            case 1:
                out[j] |= (c >> 4) & 0x3;
                j++;
                out[j] = (c & 0xf) << 4;
                break;
            case 2:
                out[j] |= (c >> 2) & 0xf;
                j++;
                out[j] = (c & 0x3) << 6;
                break;
            case 3:
                out[j] |= c;
                j++;
                break;
        }
    }
    
    // Trim result to actual length j
    return new Uint8Array(out.slice(0, j));
}

module.exports = {
    base64_encode,
    base64_decode
};
