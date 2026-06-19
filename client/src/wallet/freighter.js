/**
 * Freighter wallet integration for submitting deposit transactions.
 *
 * VERIFY: @stellar/freighter-api method signatures against latest docs.
 */

import {
    isConnected,
    requestAccess,
    signTransaction,
    getNetworkDetails,
} from '@stellar/freighter-api';

export async function connectWallet() {
    const connected = await isConnected();
    if (!connected.isConnected) throw new Error('Freighter not installed');
    const access = await requestAccess();
    return access.address;
}

export async function getNetwork() {
    const details = await getNetworkDetails();
    return {
        network:    details.network,
        networkUrl: details.networkUrl,
        passphrase: details.networkPassphrase,
    };
}

export async function signAndSubmit(txXdr, networkPassphrase) {
    const signed = await signTransaction(txXdr, {
        networkPassphrase,
    });
    return signed.signedTxXdr;
}
