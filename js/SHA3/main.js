const { sha3_256Sync, sha3_512Sync, sha3_256Async, sha3_512Async } = require('./SHA3');

const input = '123456';

function hex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
}

const nodeCrypto = typeof require !== 'undefined' && require('crypto');
const hasSHA3 = nodeCrypto && nodeCrypto.getHashes && nodeCrypto.getHashes().includes('sha3-256');

if (hasSHA3) {
  console.log('SHA3-256:', hex(sha3_256Sync(input)));
  console.log('SHA3-512:', hex(sha3_512Sync(input)));
} else {
  Promise.all([sha3_256Async(input), sha3_512Async(input)])
    .then(([a256, a512]) => {
      console.log('SHA3-256:', hex(a256));
      console.log('SHA3-512:', hex(a512));
    })
    .catch(e => console.error(e.message));
}
