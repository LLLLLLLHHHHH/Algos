
const XXTEA = require('./XXTEA');

function main() {
    const value = new Uint32Array([1, 2]);
    const key = new Uint32Array([1, 2, 3, 4]);
    const n = 2;

    console.log(`加密前原始数据：${value[0].toString(16)} ${value[1].toString(16)}`);
    XXTEA.encrypt(n, value, key);
    console.log(`加密后数据：${value[0].toString(16)} ${value[1].toString(16)}`);
    XXTEA.decrypt(n, value, key);
    console.log(`解密后数据：${value[0].toString(16)} ${value[1].toString(16)}`);
}

main();
