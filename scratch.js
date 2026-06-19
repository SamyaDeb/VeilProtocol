import { rpc } from '@stellar/stellar-sdk';
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
    console.log(res.events?.length, "events found");
}
syncTreeLeaves();
