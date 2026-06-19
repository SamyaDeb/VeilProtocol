const { buildPoseidon } = require('./node_modules/circomlibjs');
async function run() {
    const poseidon = await buildPoseidon();
    const F = poseidon.F;
    const res = poseidon([1, 2]);
    console.log(F.toString(res, 16));
}
run();
