const { hmacSync, hmacAsync } = require('./HMAC');

const key = 'key';
const message = 'hello';

function hex(u8) {
  return Array.from(u8).map(b => b.toString(16).padStart(2, '0')).join('');
}

if (typeof require !== 'undefined' && require('crypto')) {
  console.log('HMAC-SHA256:', hex(hmacSync(key, message, 'sha256')));
  console.log('HMAC-SHA384:', hex(hmacSync(key, message, 'sha384')));
  console.log('HMAC-SHA512:', hex(hmacSync(key, message, 'sha512')));
} else {
  Promise.all([
    hmacAsync(key, message, 'sha256'),
    hmacAsync(key, message, 'sha384'),
    hmacAsync(key, message, 'sha512')
  ]).then(([a256, a384, a512]) => {
    console.log('HMAC-SHA256:', hex(a256));
    console.log('HMAC-SHA384:', hex(a384));
    console.log('HMAC-SHA512:', hex(a512));
  }).catch(e => console.error(e.message));
}
