const fs = require('fs');

let content = fs.readFileSync('contracts/asp/src/lib.rs', 'utf8');

const mdsBytes = fs.readFileSync('mds_bytes.rs', 'utf8');

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
content = content.substring(0, startIdx) + newMds + '\n\n    ' + content.substring(endIdx);

fs.writeFileSync('contracts/asp/src/lib.rs', content);
