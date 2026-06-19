const fs = require('fs');
const mdsHex = [
        [
            "109b7f411ba0e4c9b2b70caf5c36a7b194be7c11ad24378bfedb68592ba8118b",
            "16ed41e13bb9c0c66ae119424fddbcbc9314dc9fdbdeea55d6c64543dc4903e0",
            "2b90bba00fca0589f617e7dcbfe82e0df706ab640ceb247b791a93b74e36736d",
        ],
        [
            "2969f27eed31a480b9c36c764379dbca2cc8fdd1415c3dded62940bcde0bd771",
            "2e2419f9ec02ec394c9871c832963dc1b89d743c8c7b964029b2311687b1fe23",
            "101071f0032379b697315876690f053d148d4e109f5fb065c8aacc55a0f89bfa",
        ],
        [
            "143021ec686a3f330d5f9e654638065ce6cd79e28c5b3753326244ee65a1b1a7",
            "176cc029695ad02582a70eff08a6fd99d057e12e58e7d7b6b16cdfabc8ee2911",
            "19a3fc0a56702bf417ba7fee3802593fa644470307043f7773279cd71d25d5e0",
        ]
];
let rs = 'let mds_bytes = [\n';
for(let i=0; i<3; i++){
    rs += '    [\n';
    for(let j=0; j<3; j++) {
        let hex = mdsHex[i][j].padStart(64, '0');
        let bytes = [];
        for(let k=0; k<32; k++) {
            bytes.push('0x' + hex.substring(k*2, k*2+2));
        }
        rs += '        [' + bytes.join(', ') + '],\n';
    }
    rs += '    ],\n';
}
rs += '];';
fs.writeFileSync('mds_bytes.rs', rs);
