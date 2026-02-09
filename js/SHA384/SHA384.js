/**
 * SHA-384: uses Node crypto or Web Crypto API.
 * Same digest as SHA-512 truncated to 384 bits (FIPS 180-4).
 */
const nodeCrypto = typeof require !== 'undefined' && require('crypto');

function toBytes(input) {
  if (typeof input === 'string') {
    const b = new Uint8Array(input.length);
    for (let i = 0; i < input.length; i++) b[i] = input.charCodeAt(i) & 0xff;
    return b;
  }
  return input instanceof Uint8Array ? input : new Uint8Array(input);
}

async function sha384Async(input) {
  const data = toBytes(input);
  if (nodeCrypto) {
    return new Uint8Array(nodeCrypto.createHash('sha384').update(Buffer.from(data)).digest());
  }
  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const buf = await crypto.subtle.digest('SHA-384', data);
    return new Uint8Array(buf);
  }
  throw new Error('SHA-384 requires Node crypto or Web Crypto API');
}

function sha384Sync(input) {
  if (nodeCrypto) {
    const data = typeof input === 'string' ? input : Buffer.from(input);
    return new Uint8Array(nodeCrypto.createHash('sha384').update(data).digest());
  }
  throw new Error('SHA-384 sync requires Node.js crypto');
}

module.exports = { sha384Async, sha384Sync, toBytes };
