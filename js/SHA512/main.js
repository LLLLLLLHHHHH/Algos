const { sha512Sync, sha512Async } = require('./SHA512');

const input = '123456';

if (typeof require !== 'undefined' && require('crypto')) {
  const out = sha512Sync(input);
  console.log(Array.from(out).map(b => b.toString(16).padStart(2, '0')).join(''));
} else {
  sha512Async(input).then(out => {
    console.log(Array.from(out).map(b => b.toString(16).padStart(2, '0')).join(''));
  });
}
