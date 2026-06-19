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
            const t0 = typeof ev.topic[0] === 'string'
                ? xdr.ScVal.fromXDR(ev.topic[0], 'base64').sym().toString()
                : ev.topic[0].sym().toString();
            if (t0 === 'leaf') {
                const cm = typeof ev.value === 'string'
                    ? xdr.ScVal.fromXDR(ev.value, 'base64').bytes()
                    : ev.value.bytes();
                leaves.push(BigInt(`0x${cm.toString('hex')}`));
            }
        } catch (e) {
            console.error(e);
        }
    }
    console.log("Leaves parsed:", leaves.length);
}
syncTreeLeaves();
