
const SHA256 = require('./SHA256');

function main() {
    const input = "123456";
    
    const sha256 = new SHA256();
    sha256.update(input);
    const output = sha256.finish();
    
    let hex = '';
    for (let i = 0; i < output.length; i++) {
        let h = output[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    
    console.log(hex);
}

main();
