
const MD5 = require('./MD5');

function main() {
    const input = "123456e10adc3949ba59abbe56e057f20f883e";
    
    const md5 = new MD5();
    md5.update(input);
    const output = md5.finish();
    
    let hex = '';
    for (let i = 0; i < output.length; i++) {
        let h = output[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    
    console.log(hex);
}

main();
