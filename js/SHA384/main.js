const { sha384Sync, sha384Async } = require('./SHA384');

const input = '123456';

if (typeof require !== 'undefined' && require('crypto')) {
  const out = sha384Sync(input);
  console.log(Array.from(out).map(b => b.toString(16).padStart(2, '0')).join(''));
} else {
  sha384Async(input).then(out => {
    console.log(Array.from(out).map(b => b.toString(16).padStart(2, '0')).join(''));
  });
}
