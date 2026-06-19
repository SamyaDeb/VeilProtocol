const fs = require('fs');

const constantsSrc = fs.readFileSync('constants_195.rs', 'utf8');

function updateFile(file) {
    let content = fs.readFileSync(file, 'utf8');
    
    // Find round_constants_t3 function
    const startIdx = content.indexOf('fn round_constants_t3');
    if (startIdx === -1) throw new Error("not found in " + file);
    
    // Find the end of it (next fn)
    let endIdx = content.indexOf('pub fn poseidon2', startIdx);
    if (endIdx === -1) throw new Error("end not found in " + file);
    
    const newFn = `fn round_constants_t3(env: &soroban_sdk::Env) -> soroban_sdk::Vec<soroban_sdk::Vec<soroban_sdk::U256>> {
${constantsSrc}
        let mut rc: soroban_sdk::Vec<soroban_sdk::Vec<soroban_sdk::U256>> = soroban_sdk::Vec::new(env);
        for r in 0usize..65 {
            let mut row: soroban_sdk::Vec<soroban_sdk::U256> = soroban_sdk::Vec::new(env);
            row.push_back(u256_from_hex64(env, flat[r * 3]));
            row.push_back(u256_from_hex64(env, flat[r * 3 + 1]));
            row.push_back(u256_from_hex64(env, flat[r * 3 + 2]));
            rc.push_back(row);
        }
        rc
    }

`;
    
    content = content.substring(0, startIdx) + newFn + content.substring(endIdx);
    fs.writeFileSync(file, content);
}

updateFile('contracts/veil_core/src/poseidon.rs');
