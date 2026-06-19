const fs = require('fs');

let content = fs.readFileSync('contracts/asp/src/lib.rs', 'utf8');

const rcBytes = fs.readFileSync('constants_195_bytes.rs', 'utf8');

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
let startIdx = content.indexOf('fn round_constants_t3');
let endIdx = content.indexOf('    fn poseidon2');
if (endIdx === -1) endIdx = content.indexOf('pub fn poseidon2');
content = content.substring(0, startIdx) + newRc + '\n\n' + content.substring(endIdx);

fs.writeFileSync('contracts/asp/src/lib.rs', content);
