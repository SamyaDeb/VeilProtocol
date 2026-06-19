import { rpc, Contract, xdr, Networks } from '@stellar/stellar-sdk';
import 'dotenv/config';

function toBytesN(hex) { return xdr.ScVal.scvBytes(Buffer.from(hex.padStart(64, '0').slice(0, 64), 'hex')); }

async function main() {
    const server = new rpc.Server('https://soroban-testnet.stellar.org');
    const contract = new Contract(process.env.ASP);
    
    const tx = new rpc.TransactionBuilder(await server.getAccount(process.env.ADMIN), { fee: '100000', networkPassphrase: Networks.TESTNET })
        .addOperation(contract.call('poseidon2', toBytesN('1'), toBytesN('2')))
        .setTimeout(30).build();
    
    try {
        const sim = await server.simulateTransaction(tx);
        console.log("sim result:", sim.result ? sim.result.retval.bytes().toString('hex') : sim.error);
    } catch(e) {
        console.error("Simulation failed:", e);
    }
}
main();
