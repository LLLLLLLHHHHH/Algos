
// XXTEA.js
// Ported from c/XXTEA/XXTEA.c

class XXTEA {
    static encrypt(n, data, key) {
        const delta = 0x9E3779B9;
        let num_rounds = 6 + Math.floor(52 / n);
        let sum = 0;
        let y, z = data[n - 1];
        let p, e;

        do {
            sum = (sum + delta) >>> 0;
            e = (sum >>> 2) & 3;
            for (p = 0; p < n - 1; ++p) {
                y = data[p + 1];
                const mx = ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
                data[p] = (data[p] + mx) >>> 0;
                z = data[p];
            }
            y = data[0];
            const mx = ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
            data[n - 1] = (data[n - 1] + mx) >>> 0;
            z = data[n - 1];
        } while (--num_rounds);
    }

    static decrypt(n, data, key) {
        const delta = 0x9E3779B9;
        let num_rounds = 6 + Math.floor(52 / n);
        let sum = (num_rounds * delta) >>> 0;
        let y = data[0], z;
        let p, e;

        do {
            e = (sum >>> 2) & 3;
            for (p = n - 1; p > 0; --p) {
                z = data[p - 1];
                const mx = ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
                data[p] = (data[p] - mx) >>> 0;
                y = data[p];
            }
            z = data[n - 1];
            const mx = ((((z >>> 5) ^ (y << 2)) + ((y >>> 3) ^ (z << 4))) ^ ((sum ^ y) + (key[(p & 3) ^ e] ^ z))) >>> 0;
            data[0] = (data[0] - mx) >>> 0;
            y = data[0];
            sum = (sum - delta) >>> 0;
        } while (--num_rounds);
    }
}

module.exports = XXTEA;
