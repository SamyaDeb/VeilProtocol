import { proveAddLiquidity, proveRemoveLiquidity, serializeProof, serializePublicInputs } from '../prover/lp.js';
import { encryptNoteForAuditor } from '../viewkey/encrypt.js';
import { selectInputs } from '../wallet/selector.js'; // Assuming a selector exists

/**
 * Liquidity UI Form Logic
 * Demonstrates how the frontend handles adding and removing shielded liquidity
 * and proving fee accrual locally.
 */

export class LiquidityForm {
    constructor(ammPoolId, veilCoreId, rpcUrl, committeePk, auditorPk) {
        this.ammPoolId = ammPoolId;
        this.veilCoreId = veilCoreId;
        this.rpcUrl = rpcUrl;
        this.committeePk = committeePk;
        this.auditorPk = auditorPk;
    }

    /**
     * Compute the provable accrued fees for a given LP position locally.
     * @param {object} lpNote The LP note containing amount (shares)
     * @param {BigInt[]} currentReserves The current on-chain reserves [reserve_0, reserve_1]
     * @param {BigInt} currentTotalShares The current total LP shares
     * @returns {object} { principal_0, principal_1, fee_0, fee_1, total_0, total_1 }
     */
    computeAccruedFees(lpNote, currentReserves, currentTotalShares) {
        const shares = BigInt(lpNote.amount);
        if (currentTotalShares === 0n) {
            return { principal_0: 0n, principal_1: 0n, fee_0: 0n, fee_1: 0n, total_0: 0n, total_1: 0n };
        }

        // The LP note metadata should ideally store the reserve state at deposit time
        // For simplicity in UI, we calculate current value vs deposit value
        const current_value_0 = (shares * BigInt(currentReserves[0])) / BigInt(currentTotalShares);
        const current_value_1 = (shares * BigInt(currentReserves[1])) / BigInt(currentTotalShares);

        // Assume we tracked deposit value in the note's metadata or local DB
        const deposit_value_0 = BigInt(lpNote.deposit_value_0 || 0n);
        const deposit_value_1 = BigInt(lpNote.deposit_value_1 || 0n);

        const fee_0 = current_value_0 > deposit_value_0 ? current_value_0 - deposit_value_0 : 0n;
        const fee_1 = current_value_1 > deposit_value_1 ? current_value_1 - deposit_value_1 : 0n;

        return {
            principal_0: deposit_value_0,
            principal_1: deposit_value_1,
            fee_0,
            fee_1,
            total_0: current_value_0,
            total_1: current_value_1
        };
    }

    /**
     * Handle the "Add Liquidity" form submission.
     */
    async handleAddLiquidity(amount0, asset0, amount1, asset1, walletState, currentReserves, currentTotalShares, reserveBlinding, currentRoot) {
        console.log(`Adding liquidity: ${amount0} of Asset ${asset0} and ${amount1} of Asset ${asset1}`);

        // RULE 2: selectInputs handles BOTH deposit notes and swap-output notes seamlessly
        const inputNotes0 = selectInputs(walletState.notes, asset0, amount0);
        const inputNotes1 = selectInputs(walletState.notes, asset1, amount1);

        if (!inputNotes0 || !inputNotes1) {
            throw new Error('Insufficient balance or no valid notes found for the requested amounts.');
        }

        // For simplicity, assume exact matching notes were found
        const inputNote0 = inputNotes0[0];
        const inputNote1 = inputNotes1[0];

        console.log('Generating AddLiquidity proof...');
        const addResult = await proveAddLiquidity(
            inputNote0, inputNote1,
            currentReserves, currentTotalShares, reserveBlinding, currentRoot
        );

        console.log('AddLiquidity proof generated.');
        
        // Form the payload to be signed by the user's wallet
        const payload = {
            proof: serializeProof(addResult.proof),
            root: currentRoot,
            nf_in_0: addResult.nf_in_0,
            nf_in_1: addResult.nf_in_1,
            lp_commit: addResult.lp_commit,
            post_reserve_cm: addResult.post_reserve_cm
        };

        return payload;
    }

    /**
     * Handle the "Remove Liquidity" form submission.
     */
    async handleRemoveLiquidity(lpNote, intent, currentReserves, currentTotalShares, reserveBlinding, currentRoot) {
        console.log(`Removing liquidity for LP Note: ${lpNote.cm}`);

        console.log('Generating RemoveLiquidity proof...');
        const remResult = await proveRemoveLiquidity(
            lpNote, intent, currentReserves, currentTotalShares, reserveBlinding, currentRoot
        );

        console.log('RemoveLiquidity proof generated.');

        // Form the payload
        const payload = {
            proof: serializeProof(remResult.proof),
            root: currentRoot,
            lp_nf: remResult.lp_nf,
            cm_out_0: remResult.cm_out_0,
            cm_out_1: remResult.cm_out_1,
            post_reserve_cm: remResult.post_reserve_cm
        };

        return payload;
    }
}
