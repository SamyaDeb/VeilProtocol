const fs = require('fs');

let content = fs.readFileSync('contracts/veil_core/src/poseidon.rs', 'utf8');

const mdsBytes = fs.readFileSync('mds_bytes.rs', 'utf8');
const rcBytes = fs.readFileSync('constants_195_bytes.rs', 'utf8');

// replace mds_t3
let newMds = `fn mds_t3(env: &Env) -> Vec<Vec<U256>> {
${mdsBytes}
    let mut rows: Vec<Vec<U256>> = Vec::new(env);
    for i in 0..3 {
        let mut row: Vec<U256> = Vec::new(env);
        for j in 0..3 {
            let bn = soroban_sdk::BytesN::from_array(env, &mds_bytes[i][j]);
            row.push_back(U256::from_be_bytes(env, bn.as_ref()));
        }
        rows.push_back(row);
    }
    rows
}`;
let startIdx = content.indexOf('fn mds_t3');
let endIdx = content.indexOf('fn round_constants_t3');
content = content.substring(0, startIdx) + newMds + '\n\n' + content.substring(endIdx);

// replace round_constants_t3
let newRc = `fn round_constants_t3(env: &Env) -> Vec<Vec<U256>> {
${rcBytes}
    let mut rc: Vec<Vec<U256>> = Vec::new(env);
    for r in 0usize..65 {
        let mut row: Vec<U256> = Vec::new(env);
        let bn1 = soroban_sdk::BytesN::from_array(env, &flat_bytes[r * 3]);
        let bn2 = soroban_sdk::BytesN::from_array(env, &flat_bytes[r * 3 + 1]);
        let bn3 = soroban_sdk::BytesN::from_array(env, &flat_bytes[r * 3 + 2]);
        row.push_back(U256::from_be_bytes(env, bn1.as_ref()));
        row.push_back(U256::from_be_bytes(env, bn2.as_ref()));
        row.push_back(U256::from_be_bytes(env, bn3.as_ref()));
        rc.push_back(row);
    }
    rc
}`;
startIdx = content.indexOf('fn round_constants_t3');
endIdx = content.indexOf('pub fn poseidon2');
content = content.substring(0, startIdx) + newRc + '\n\n' + content.substring(endIdx);

fs.writeFileSync('contracts/veil_core/src/poseidon.rs', content);
