
const base64 = require('./base64');

function main() {
    let input = "nothing";
    
    // Encode
    let encoded = base64.base64_encode(input);
    console.log(encoded);
    
    // Decode
    let decodedBytes = base64.base64_decode(encoded);
    
    // Convert bytes back to string
    let decodedStr = "";
    if (decodedBytes) {
        for (let i = 0; i < decodedBytes.length; i++) {
            decodedStr += String.fromCharCode(decodedBytes[i]);
        }
    }
    console.log(decodedStr);
}

main();
