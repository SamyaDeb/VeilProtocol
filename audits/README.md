# Veil Protocol Audits

## Scope Statement

### Audit Pass 1 (Soroban Contracts + M1/M3 Circuits)
**Scope:** `veil_core`, `asp`, `amm_pool`, `viewkey`, and `circuits/{deposit,transfer,withdraw,swap,batch_settle,settle_or_refund,kyc_credential}` along with the trusted setup review. 
Auditors should verify all logic against the `SECURITY.md` checklist. Please refer to the ceremony transcripts in `circuit-keys/ceremony-transcript.txt` and ensure `vk-convert` produces valid outputs.

### Audit Pass 2 (Lending + Liquidation)
**Scope:** `lending`, `circuits/{lend,repay,liquidate}`, oracle binding, liquidation path.
This is an isolated module because of its high risk. Auditors should specifically review oracle staleness checks and price bindings to circuit public inputs.

All findings should be logged in `findings.md`.
