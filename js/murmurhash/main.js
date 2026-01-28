
const murmurhash = require('./murmurhash');

function main() {
    const seed = 0;
    const key = "CSSStyleDeclaration";
    
    // JS strings are utf-16, but C code treats char* as bytes.
    // "CSSStyleDeclaration" contains only ASCII, so direct charCodeAt matches.
    
    const hash = murmurhash(key, seed);
    
    // Print as signed 32-bit integer to match C %d format
    // Or unsigned? C %d is signed int. uint32_t passed to %d might be printed as signed.
    // The C example output will clarify.
    // Let's print both.
    
    console.log(`murmurhash(${key}) = ${hash >>> 0} (unsigned)`);
    console.log(`murmurhash(${key}) = ${hash | 0} (signed)`);
}

main();
