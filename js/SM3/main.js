
const SM3 = require('./SM3');

function main() {
    const input = "abcabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd";
    
    console.log("Message: " + input);

    const sm3 = new SM3();
    sm3.update(input);
    const output = sm3.finish();
    
    let hex = '';
    for (let i = 0; i < output.length; i++) {
        let h = output[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    
    console.log("Hash: " + hex);
}

main();
