/**
 * HMAC: Hash-based Message Authentication Code.
 * Supports HMAC-MD5, HMAC-SHA1, HMAC-SHA256, HMAC-SHA384, HMAC-SHA512 (and SHA3 when available).
 * Uses Node crypto or Web Crypto API.
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

const algMap = {
  'sha1': 'SHA-1',
  'sha256': 'SHA-256',
  'sha384': 'SHA-384',
  'sha512': 'SHA-512',
  'sha3-256': 'SHA-3-256',
  'sha3-512': 'SHA-3-512'
};

async function hmacAsync(key, message, hashAlg) {
  const keyBytes = toBytes(key);
  const msgBytes = toBytes(message);
  const alg = (hashAlg || 'sha256').toLowerCase().replace('-', '');

  if (nodeCrypto) {
    const name = alg === 'sha3256' ? 'sha3-256' : alg === 'sha3512' ? 'sha3-512' : alg;
    const hmac = nodeCrypto.createHmac(name, Buffer.from(keyBytes));
    hmac.update(Buffer.from(msgBytes));
    return new Uint8Array(hmac.digest());
  }

  if (typeof crypto !== 'undefined' && crypto.subtle) {
    const webAlg = algMap[alg] || algMap.sha256;
    const cryptoKey = await crypto.subtle.importKey(
      'raw',
      keyBytes,
      { name: 'HMAC', hash: webAlg },
      false,
      ['sign']
    );
    const sig = await crypto.subtle.sign('HMAC', cryptoKey, msgBytes);
    return new Uint8Array(sig);
  }

  throw new Error('HMAC requires Node crypto or Web Crypto API');
}

function hmacSync(key, message, hashAlg) {
  if (nodeCrypto) {
    const alg = (hashAlg || 'sha256').toLowerCase();
    const hmac = nodeCrypto.createHmac(alg, typeof key === 'string' ? key : Buffer.from(key));
    hmac.update(typeof message === 'string' ? message : Buffer.from(message));
    return new Uint8Array(hmac.digest());
  }
  throw new Error('HMAC sync requires Node.js crypto');
}

module.exports = {
  hmacAsync,
  hmacSync,
  toBytes
};
