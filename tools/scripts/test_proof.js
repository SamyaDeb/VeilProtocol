import * as snarkjs from 'snarkjs';
const input = {
    amount: "1000", asset_id: "999", blinding: "12345", owner_pk: "12345", cred_secret: "1", issuer_pk: "456",
    asp_path: Array(20).fill("0"), asp_idx: Array(20).fill("0"),
    blocked_lower_leaf: "0", blocked_upper_leaf: "0", blocked_lower_path: Array(20).fill("0"), blocked_lower_idx: Array(20).fill("0"),
    blocked_upper_path: Array(20).fill("0"), blocked_upper_idx: Array(20).fill("0"),
    cm: "0", public_amount: "1000", asp_approved_root: "0", asp_blocked_root: "0"
};
snarkjs.groth16.fullProve(input, "circuits/build/deposit_js/deposit.wasm", "circuit-keys/dev/deposit_final.zkey").then(res => {
    console.log(JSON.stringify(res.proof.pi_b));
}).catch(console.error);
