import { rpc, Contract, xdr, Networks, TransactionBuilder } from '@stellar/stellar-sdk';
import 'dotenv/config';

function toBytesN(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0').slice(0, 64), 'hex')); }

async function main() {
    const server = new rpc.Server('https://soroban-testnet.stellar.org');
    const contract = new Contract(process.env.ASP);
    
    // poseidon([credLeaf, 0])
    const credLeaf = "0abe4a2455f21e8923217c545185493682a97960f175218d32c671647f7825a9";
    const sibling = "0000000000000000000000000000000000000000000000000000000000000000";
    const tx = new TransactionBuilder(await server.getAccount(process.env.ADMIN), { fee: '100000', networkPassphrase: Networks.TESTNET })
        .addOperation(contract.call('poseidon2', toBytesN(credLeaf), toBytesN(sibling)))
        .setTimeout(30).build();
    
    try {
        const sim = await server.simulateTransaction(tx);
        console.log("sim result:", sim.result ? sim.result.retval.bytes().toString('hex') : sim.error);
    } catch(e) {
        console.error("Simulation failed:", e);
    }
}
main();
