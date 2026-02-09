/**
 * SHA3-256 and SHA3-512: uses Node crypto or Web Crypto API (FIPS 202).
 * Node 19+ and modern browsers support SHA3.
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

async function sha3_256Async(input) {
  const data = toBytes(input);
  if (nodeCrypto && nodeCrypto.getHashes && nodeCrypto.getHashes().includes('sha3-256')) {
    return new Uint8Array(nodeCrypto.createHash('sha3-256').update(Buffer.from(data)).digest());
  }
  if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
    const buf = await crypto.subtle.digest('SHA-3-256', data);
    return new Uint8Array(buf);
  }
  throw new Error('SHA3-256 requires Node 19+ crypto or Web Crypto API with SHA-3');
}

async function sha3_512Async(input) {
  const data = toBytes(input);
  if (nodeCrypto && nodeCrypto.getHashes && nodeCrypto.getHashes().includes('sha3-512')) {
    return new Uint8Array(nodeCrypto.createHash('sha3-512').update(Buffer.from(data)).digest());
  }
  if (typeof crypto !== 'undefined' && crypto.subtle && crypto.subtle.digest) {
    const buf = await crypto.subtle.digest('SHA-3-512', data);
    return new Uint8Array(buf);
  }
  throw new Error('SHA3-512 requires Node 19+ crypto or Web Crypto API with SHA-3');
}

function sha3_256Sync(input) {
  if (nodeCrypto && nodeCrypto.getHashes && nodeCrypto.getHashes().includes('sha3-256')) {
    const data = typeof input === 'string' ? input : Buffer.from(input);
    return new Uint8Array(nodeCrypto.createHash('sha3-256').update(data).digest());
  }
  throw new Error('SHA3-256 sync requires Node.js 19+ crypto');
}

function sha3_512Sync(input) {
  if (nodeCrypto && nodeCrypto.getHashes && nodeCrypto.getHashes().includes('sha3-512')) {
    const data = typeof input === 'string' ? input : Buffer.from(input);
    return new Uint8Array(nodeCrypto.createHash('sha3-512').update(data).digest());
  }
  throw new Error('SHA3-512 sync requires Node.js 19+ crypto');
}

module.exports = {
  sha3_256Async,
  sha3_512Async,
  sha3_256Sync,
  sha3_512Sync,
  toBytes
};
