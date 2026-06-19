const { buildPoseidon } = require('circomlibjs');
async function main() {
    const p = await buildPoseidon();
    const F = p.F;
    const credLeaf = BigInt('4859341136979446312008335051623763697861449035266247323201369060140362769833');
    const target = "04731f0a0b897be526c59b99d1063cb3b3a7fc41a1fd3b1107969f0b990c26f2";
    
    const cases = [
        [0n, credLeaf],
        [credLeaf, 0n],
        [credLeaf, credLeaf],
        [0n, 0n],
        [1n, credLeaf],
        [credLeaf, 1n]
    ];
    for (const c of cases) {
        if (F.toString(p(c), 16).padStart(64, '0') === target) {
            console.log("Found!", c);
            return;
        }
    }
    // try capacity permutations?
    // In JS, circomlibjs doesn't let you directly change capacity.
    console.log("Not found in obvious cases.");
}
main();
