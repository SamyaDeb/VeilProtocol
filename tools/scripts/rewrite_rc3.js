const fs = require('fs');

const data = JSON.parse(fs.readFileSync('node_modules/circomlibjs/src/poseidon_constants.json'));
const c = data.C[1];
let rs = 'let flat_bytes = [\n';
for(let i=0; i<c.length; i++){
    let hex = c[i].replace('0x', '').padStart(64, '0');
    let bytes = [];
    for(let j=0; j<32; j++) {
        bytes.push('0x' + hex.substring(j*2, j*2+2));
    }
    rs += '    [' + bytes.join(', ') + '],\n';
}
rs += '];';
fs.writeFileSync('constants_195_bytes.rs', rs);
