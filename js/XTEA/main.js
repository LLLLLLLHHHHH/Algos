
const XTEA = require('./XTEA');

function main() {
    const value = new Uint32Array([1, 2]);
    const key = new Uint32Array([1, 2, 3, 4]);
    const num_rounds = 32;

    console.log(`加密前原始数据：${value[0].toString(16)} ${value[1].toString(16)}`);
    XTEA.encrypt(num_rounds, value, key);
    console.log(`加密后原始数据：${value[0].toString(16)} ${value[1].toString(16)}`);
    XTEA.decrypt(num_rounds, value, key);
    console.log(`解密后原始数据：${value[0].toString(16)} ${value[1].toString(16)}`);
}

main();
