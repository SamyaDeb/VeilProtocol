import { xdr, rpc } from '@stellar/stellar-sdk';
const RPC_URL = process.env.SOROBAN_RPC || 'https://soroban-testnet.stellar.org';
const server = new rpc.Server(RPC_URL);
const coreId = process.env.VEIL_CORE;
async function syncTreeLeaves() {
    const latest = await server.getLatestLedger();
    const startLedger = Math.max(1, latest.sequence - 2000);
    const res = await server.getEvents({
        startLedger,
        filters: [{ type: 'contract', contractIds: [coreId] }],
        limit: 10000,
    });
    const leaves = [];
    for (const ev of res.events ?? []) {
        try {
            const topic = typeof ev.topic[0] === 'string' ? xdr.ScVal.fromXDR(ev.topic[0], 'base64') : ev.topic[0];
            const sym = topic.sym().toString();
            if (sym === 'leaf') {
                const val = typeof ev.value === 'string' ? xdr.ScVal.fromXDR(ev.value, 'base64') : ev.value;
                const cmBytes = val.bytes();
                leaves.push(BigInt(`0x${cmBytes.toString('hex')}`));
            }
        } catch (e) { console.error("Error", e); }
    }
    console.log("Leaves parsed:", leaves.length);
}
syncTreeLeaves();
