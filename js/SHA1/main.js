
const SHA1 = require('./SHA1');

function main() {
    const data = "abc";
    console.log("Message: " + data);

    const sha1 = new SHA1();
    sha1.update(data);
    const digest = sha1.final();

    let hex = "";
    for (let i = 0; i < digest.length; i++) {
        let h = digest[i].toString(16);
        if (h.length < 2) h = '0' + h;
        hex += h;
    }
    
    console.log("SHA1: " + hex);

    const expected = "a9993e364706816aba3e25717850c26c9cd0d89d";
    console.log("Expect: " + expected);
}

main();
