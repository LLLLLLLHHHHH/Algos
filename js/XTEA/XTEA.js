
// XTEA.js
// Ported from c/XTEA/XTEA.c

class XTEA {
    static encrypt(num_rounds, data, key) {
        let v0 = data[0];
        let v1 = data[1];
        let sum = 0;
        const delta = 0x9E3779B9;

        const k0 = key[0];
        const k1 = key[1];
        const k2 = key[2];
        const k3 = key[3];

        for (let i = 0; i < num_rounds; i++) {
            v0 = (v0 + (((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3])) >>> 0)) >>> 0;
            sum = (sum + delta) >>> 0;
            v1 = (v1 + (((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3])) >>> 0)) >>> 0;
        }

        data[0] = v0;
        data[1] = v1;
    }

    static decrypt(num_rounds, data, key) {
        let v0 = data[0];
        let v1 = data[1];
        const delta = 0x9E3779B9;
        let sum = (delta * num_rounds) >>> 0;

        const k0 = key[0];
        const k1 = key[1];
        const k2 = key[2];
        const k3 = key[3];

        for (let i = 0; i < num_rounds; i++) {
            v1 = (v1 - (((((v0 << 4) ^ (v0 >>> 5)) + v0) ^ (sum + key[(sum >>> 11) & 3])) >>> 0)) >>> 0;
            sum = (sum - delta) >>> 0;
            v0 = (v0 - (((((v1 << 4) ^ (v1 >>> 5)) + v1) ^ (sum + key[sum & 3])) >>> 0)) >>> 0;
        }

        data[0] = v0;
        data[1] = v1;
    }
}

module.exports = XTEA;
