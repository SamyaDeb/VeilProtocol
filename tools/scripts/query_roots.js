const { rpc, Contract, xdr, Address, TransactionBuilder } = require('@stellar/stellar-sdk');
async function run() {
    const server = new rpc.Server('https://soroban-testnet.stellar.org');
    const contract = new Contract(process.env.ASP);
    let sim = await server.simulateTransaction(
        new TransactionBuilder(await server.getAccount('GCK73PA3EUPAI7FLQ6WXDNZGOQZJB3MA6RTCBRGIMP7QUOIZL7KSZGAA'), { fee: '1000', networkPassphrase: 'Test SDF Network ; September 2015' })
        .addOperation(contract.call('blocked_root'))
        .setTimeout(30).build()
    );
    console.log("blocked_root:", sim.result.retval.bytes().toString('hex'));
}
run();
