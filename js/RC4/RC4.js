
// RC4.js
// Ported from c/RC4/RC4.c

class RC4 {
    constructor() {
        this.S = new Uint8Array(256);
    }

    swap(i, j) {
        let temp = this.S[i];
        this.S[i] = this.S[j];
        this.S[j] = temp;
    }

    init_sbox(key) {
        const keyLen = key.length;
        // Init S-box
        for (let i = 0; i < 256; ++i) {
            this.S[i] = i;
        }

        let T = new Uint8Array(256);
        // Init T table based on key
        for (let i = 0; i < 256; ++i) {
            T[i] = key[i % keyLen];
        }

        // Shuffle S-box
        let j = 0;
        for (let i = 0; i < 256; ++i) {
            j = (j + this.S[i] + T[i]) % 256;
            this.swap(i, j);
        }
    }

    encrypt(data, key) {
        // Convert string key to Uint8Array if needed
        let keyBytes;
        if (typeof key === 'string') {
            keyBytes = new Uint8Array(key.length);
            for (let i = 0; i < key.length; i++) {
                keyBytes[i] = key.charCodeAt(i);
            }
        } else {
            keyBytes = key;
        }

        this.init_sbox(keyBytes);

        // Convert string data to Uint8Array if needed (for in-place modification simulation)
        // But in JS strings are immutable. We will return a new Uint8Array or Buffer.
        let dataBytes;
        let isString = false;
        if (typeof data === 'string') {
            isString = true;
            dataBytes = new Uint8Array(data.length);
            for (let i = 0; i < data.length; i++) {
                dataBytes[i] = data.charCodeAt(i);
            }
        } else {
            dataBytes = data; // Assuming Uint8Array or Buffer
        }

        let i = 0;
        let j = 0;
        let k, t;

        for (let h = 0; h < dataBytes.length; ++h) {
            i = (i + 1) % 256;
            j = (j + this.S[i]) % 256;
            this.swap(i, j);

            t = (this.S[i] + this.S[j]) % 256;
            k = this.S[t];
            dataBytes[h] ^= k;
        }

        if (isString) {
            // For RC4, encrypted bytes might not be valid UTF-8, so returning string might be lossy/corrupted if printed directly.
            // But to match C behavior "printf", we can try to return string.
            // However, C uses char* which is bytes.
            // If we want to emulate C exactly, we should return the bytes, or a string where chars are 0-255.
            let res = "";
            for (let x = 0; x < dataBytes.length; x++) {
                res += String.fromCharCode(dataBytes[x]);
            }
            return res;
        }

        return dataBytes;
    }
}

module.exports = RC4;
