
const TEA = require('./TEA');

function main() {
    const v = new Uint32Array([1, 2]);
    const k = new Uint32Array([1, 2, 3, 4]);

    console.log(`加密前的数据：${v[0].toString(16)} ${v[1].toString(16)}`);
    TEA.encrypt(v, k);
    console.log(`加密后数据：${v[0].toString(16)} ${v[1].toString(16)}`);
    TEA.decrypt(v, k);
    console.log(`解密后数据：${v[0].toString(16)} ${v[1].toString(16)}`);
}

main();
