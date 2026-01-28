
// TEA.js
// Ported from c/TEA/TEA.c

class TEA {
    static encrypt(data, key) {
        let v0 = data[0];
        let v1 = data[1];
        let sum = 0;
        const delta = 0x9e3779b9;

        const k0 = key[0];
        const k1 = key[1];
        const k2 = key[2];
        const k3 = key[3];

        for (let i = 0; i < 32; i++) {
            sum = (sum + delta) >>> 0;
            v0 = (v0 + ((((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >>> 5) + k1)) >>> 0)) >>> 0;
            v1 = (v1 + ((((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >>> 5) + k3)) >>> 0)) >>> 0;
        }

        data[0] = v0;
        data[1] = v1;
    }

    static decrypt(data, key) {
        let v0 = data[0];
        let v1 = data[1];
        const delta = 0x9e3779b9;
        let sum = (delta * 32) >>> 0;

        const k0 = key[0];
        const k1 = key[1];
        const k2 = key[2];
        const k3 = key[3];

        for (let i = 0; i < 32; i++) {
            v1 = (v1 - ((((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >>> 5) + k3)) >>> 0)) >>> 0;
            v0 = (v0 - ((((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >>> 5) + k1)) >>> 0)) >>> 0;
            sum = (sum - delta) >>> 0;
        }

        data[0] = v0;
        data[1] = v1;
    }
}

module.exports = TEA;
