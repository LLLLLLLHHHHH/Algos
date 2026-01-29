const { crc32, crc32_total } = require('./CRC32');

function main() {
    // Helper to format hex output
    const toHex = (n) => '0x' + (n >>> 0).toString(16).toUpperCase().padStart(8, '0');

    console.log("Running CRC32 Tests (JS)\n");

    // Test Vector 1: "123456789"
    // Expected CRC32: 0xCBF43926
    const data1 = "123456789";
    const result1 = crc32_total(data1);
    console.log(`Test 1: '${data1}'`);
    console.log(`Expected: 0xCBF43926`);
    console.log(`Result:   ${toHex(result1)}`);
    console.log(result1 === 0xCBF43926 ? "PASS\n" : "FAIL\n");

    // Test Vector 2: "The quick brown fox jumps over the lazy dog"
    // Expected CRC32: 0x414FA339
    const data2 = "The quick brown fox jumps over the lazy dog";
    const result2 = crc32_total(data2);
    console.log(`Test 2: '${data2}'`);
    console.log(`Expected: 0x414FA339`);
    console.log(`Result:   ${toHex(result2)}`);
    console.log(result2 === 0x414FA339 ? "PASS\n" : "FAIL\n");

    // Test 3: Segmented calculation
    // "123456789" split into "12345" and "6789"
    const part1 = "12345";
    const part2 = "6789";
    let crc = 0xFFFFFFFF;
    crc = crc32(crc, part1);
    crc = crc32(crc, part2);
    const result3 = (crc ^ 0xFFFFFFFF) >>> 0;

    console.log(`Test 3: Segmented calculation ('12345' + '6789')`);
    console.log(`Expected: 0xCBF43926`);
    console.log(`Result:   ${toHex(result3)}`);
    console.log(result3 === 0xCBF43926 ? "PASS\n" : "FAIL\n");
}

main();
