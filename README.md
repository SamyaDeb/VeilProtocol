# Veil Protocol

**Privacy-preserving DeFi on Stellar — shielded AMM, private RWA lending, and ZK compliance in one protocol.**

Veil Protocol lets institutions move, swap, and borrow against tokenized real-world assets on Stellar with amounts, counterparties, and balances completely hidden — while still allowing a regulator to audit specific positions on lawful request. Built on top of Protocol 25's native BN254 and Poseidon host functions (CAP-0074, CAP-0075).

---

## Why this exists

Stellar holds $2B+ in tokenized real-world assets (Franklin Templeton BENJI, Ondo, Centrifuge, Etherfuse). Every balance, trade, and counterparty on these venues is fully public. For regulated institutions, public-by-default settlement is a non-starter — it leaks treasury strategy and cannot satisfy client-confidentiality obligations.

Protocol 25 shipped the ZK primitives to fix this. Veil is the application layer on top.

---

## What it does

```
PUBLIC WALLET (Freighter)
  [100 BENJI — visible to everyone]
        │
        │  deposit  (ZK proof: KYC'd, not sanctioned)
        ▼
SHIELDED POOL  (veil_core on Stellar)
  ┌────────────────────────────────────────┐
  │  commitment #0  0x7f3a...  (blob)      │ ← only you can decode
  │  commitment #1  0x3b2c...  (blob)      │
  │  commitment #N  ...                    │
  └────────────────────────────────────────┘
        │ swap               │ borrow
        ▼                    ▼
  new output note      collateral locked
  (hidden amount)      borrow note created
                       (LTV proven in ZK)
        │
        │  withdraw
        ▼
PUBLIC WALLET
  [received amount]

REGULATOR  (auditor view key)
  → decrypts exactly the note(s) in scope
  → sees: amount, asset, owner public key
  → cannot spend, cannot see others
```

### Three products sharing one shielded state

| Module | What it does | What stays hidden |
|--------|-------------|-------------------|
| **Shielded AMM** | Batch-auction swaps with a threshold-decryption committee | Trade size, asset, counterparty, pool reserves |
| **Private RWA Lending** | Borrow against shielded collateral; LTV proven via Reflector oracle range proof | Collateral amount, borrow amount |
| **ZK Compliance** | KYC-gated entry (ASP) + auditor view keys for selective regulatory disclosure | User identity (from the general public) |

---

## How it works — core mechanics

### Notes (private UTXOs)

Every asset inside Veil is a **note**:

```
note = { amount, asset_id, blinding, owner_pk }
commitment = Poseidon(amount, asset_id, blinding, owner_pk)
nullifier  = Poseidon(owner_sk, leaf_index, commitment)
```

Commitments are public blobs on-chain. Notes are private — stored encrypted in the browser. Only the holder of `owner_sk` can spend a note.

### ZK proofs

Every state transition (deposit, transfer, swap, borrow, withdraw) is accompanied by a **Groth16 proof** over BN254, verified on-chain by the native CAP-0074 pairing host function. The proof convinces the contract that:

- The note being spent exists in the Merkle tree
- The spender owns it (knows `owner_sk`)
- Conservation holds (`Σ inputs = Σ outputs + public_amount`)
- Range checks pass (no negative or overflow amounts)

...without revealing any of the underlying numbers.

### Two nullifier sets (RULE 3)

`veil_core` maintains two separate nullifier sets:

| Set | When a nullifier enters | Meaning |
|-----|------------------------|---------|
| `SPENT` | Transfer / swap / withdraw | Note consumed forever |
| `LOCKED` | Collateral locked for a loan | Note frozen, cannot be spent or re-borrowed |

Every operation checks: **nullifier ∉ SPENT ∧ nullifier ∉ LOCKED** before accepting. This prevents double-spends and spending collateral while it is backing a loan — without revealing which note the nullifier belongs to.

### Auditor ciphertext (RULE 4)

Every commitment insertion also stores a ciphertext encrypted to the protocol auditor's BN254 public key. Decryption is off-chain — the contract only stores and serves the ciphertext by index. A compromised auditor key enables disclosure but never theft.

### Batch-auction AMM

Swap orders are flow-encrypted to a threshold committee key. The committee decrypts orders as a group (t-of-n), computes a single clearing price, generates a `batch_settle` ZK proof, and posts output commitments for all traders. No single committee member can decrypt alone. The settlement proof enforces value conservation — a malicious committee can stall but cannot steal.

---

## Architecture

```
circuits/         Circom circuits: deposit, transfer, withdraw, swap,
                  batch_settle, lend, kyc_credential, settle_or_refund
contracts/        Soroban/Rust: veil_core, amm_pool, lending, asp
client/           TypeScript/React: WASM prover, Freighter wallet, note store,
                  swap / lend / auditor UIs
circuit-keys/     Pinned proving + verification keys, sha256 manifest
e2e-tests/        Browser-proof → testnet-verify suites
indexer/          Node.js Soroban-RPC event indexer (persists Merkle tree)
deployments/      Network configs, contract IDs
tools/ceremony-cli/  Phase-2 trusted-setup tooling
docs/             Full technical documentation (see below)
```

### Contract call graph

```
deposit:    app → veil_core.deposit
                    ├→ asp.check_entry          (KYC gate — RULE 1)
                    ├→ verify_groth16(deposit)
                    ├→ tree.insert + auditor_ct (RULE 4)
                    └→ token.transfer(depositor → core)

swap:       app → amm_pool.submit_order
                    ├→ root_is_known
                    ├→ verify_groth16(swap)
                    └→ spend(nullifier)         (RULE 3: spent)

settle:  committee → amm_pool.settle_batch
                    ├→ verify_groth16(batch_settle)
                    └→ insert_commitment × outputs (+ auditor_ct, RULE 4)

borrow:     app → lending.open_loan
                    ├→ read_oracle_price         (Reflector)
                    ├→ verify_groth16(lend)
                    ├→ lock(collat_nullifier)    (RULE 3: locked)
                    └→ insert_commitment(borrow_note + auditor_ct)

repay:      app → lending.repay
                    ├→ spend(repay_nullifier)
                    └→ unlock(collat_nullifier)
```

---

## Circuits

| Circuit | Proves |
|---------|--------|
| `deposit.circom` | Commitment well-formed + ASP membership/non-membership |
| `transfer.circom` | Note ownership + value conservation (2-in / 2-out) |
| `withdraw.circom` | Note ownership + public output + change note |
| `swap.circom` | Note ownership + flow-encrypted intent binding |
| `batch_settle.circom` | Batch value conservation + clearing price + reserve update |
| `lend.circom` | Note ownership + LTV range proof against oracle price |
| `kyc_credential.circom` | KYC credential membership without revealing which credential |
| `settle_or_refund.circom` | Settlement OR refund — not both (prevents committee griefing) |

All circuits use **Poseidon** (CAP-0075 params, must match on-chain), **Groth16** over **BN254**, and a fixed Merkle tree depth of 32.

---

## Frontend — 7 screens

| Screen | What it does |
|--------|-------------|
| **Wallet** | Shows your shielded notes, anonymity set size, note recovery |
| **Deposit** | Brings tokens from your public wallet into the shielded pool |
| **Swap** | Submits a flow-encrypted order to the batch-auction AMM |
| **Borrow** | Locks collateral, proves LTV, mints a shielded borrow note |
| **Liquidity** | Provides liquidity to the AMM with hidden position size |
| **Withdraw** | Returns tokens from the shielded pool to a public address |
| **Auditor** | Decrypts a specific note ciphertext using the auditor key |

The browser generates Groth16 proofs locally via **snarkjs WASM** running in a Web Worker — your secret key and note plaintexts never leave the browser.

---

## Getting started

### Prerequisites

- Node.js 20+
- Rust + `soroban-cli` (for contract builds)
- Circom 2 + snarkjs (for circuit builds)
- Freighter browser wallet (testnet)

### Install

```bash
git clone https://github.com/SamyaDeb/VeilProtocol
cd VeilProtocol
npm install
cd client && npm install --legacy-peer-deps
```

### Run the frontend (testnet)

```bash
cd client
npm run dev
# Open http://localhost:5173
# Switch Freighter to Testnet
```

### Build contracts

```bash
cd contracts/veil_core  && cargo build --target wasm32-unknown-unknown --release
cd contracts/amm_pool   && cargo build --target wasm32-unknown-unknown --release
cd contracts/lending    && cargo build --target wasm32-unknown-unknown --release
cd contracts/asp        && cargo build --target wasm32-unknown-unknown --release
```

### Run contract tests

```bash
cargo test --workspace
```

### Run e2e suites (requires deployed testnet contracts)

```bash
cd e2e-tests
npm install
npm test                          # all suites
npx vitest run src/deposit.test.js   # single suite
```

### Typecheck + build frontend

```bash
cd client
npm run typecheck
npm run build
```

---

## Testnet deployment

| Contract | Address |
|----------|---------|
| `veil_core` | `CALUOS4OOU5TMEFDZZNJA4Q6LPU4QTNYG3I3KQKZJYSICFJV233CXVAW` |
| `asp` | `CBHO57DREGTP3YR5NX7TUKMOAQNJD7MPBAV5NIUNF5UP6KTBVVOSTO66` |
| `amm_pool` | `CCNOAICDH5HFB4TMM23YOCCK57D2FQXI3JMNYBKTQFPDM25E5TUS3VHM` |
| `lending` | `CAXZJRTMMR2BPATZNNSR3BLZIQZ6KT3GW2AF7R6WPR2IG23EXBC2GABA` |
| `TEST-RWA token` | `CDLZFC3SYJYDZT7K67VZ75HPJVIEUVNIXF47ZG2FB2RMQQVU2HHGCYSC` |

RPC: `https://soroban-testnet.stellar.org`

Full deployment configs: [`deployments/testnet.json`](deployments/testnet.json)

---

## Security

Veil is pre-audit software. Do not use with real assets until M7 audit completion.

Known limitations in the current build:
- Auditor encryption uses a dev XOR scheme — ECIES upgrade required before M7
- Swap flow encryption is plaintext JSON on testnet — real ElGamal-on-BN254 for M4+
- Circuit keys in `circuit-keys/dev/` are single-contributor (toxic waste known) — multi-party Phase-2 ceremony required for mainnet
- Committee is a 2-of-3 dev mock — production committee bring-up at M7

Threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md)
Security checklist: [`docs/SECURITY.md`](docs/SECURITY.md)
Bug bounty: [`docs/BUG_BOUNTY.md`](docs/BUG_BOUNTY.md)

---

## Documentation

| Doc | Contents |
|-----|---------|
| [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) | Contracts, call graph, shared state, ZK primitive map |
| [`docs/CIRCUITS.md`](docs/CIRCUITS.md) | Every circuit's inputs, constraints, and flow |
| [`docs/CONTRACTS.md`](docs/CONTRACTS.md) | Storage layout, functions, errors, TTL strategy |
| [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md) | Privacy, double-spend, setup, ASP risks + mitigations |
| [`docs/SECURITY.md`](docs/SECURITY.md) | Audit readiness checklist |
| [`docs/TEST_PLAN.md`](docs/TEST_PLAN.md) | Unit / integration / e2e + per-milestone verify commands |
| [`docs/ROADMAP.md`](docs/ROADMAP.md) | Vertical slices mapped to SCF v7.0 tranches |
| [`docs/RUNBOOK.md`](docs/RUNBOOK.md) | Operational runbook: oracle outage, committee halt, key rotation |

---

## Technical stack

| Layer | Technology |
|-------|-----------|
| Blockchain | Stellar / Soroban (Protocol 25) |
| Smart contracts | Rust + soroban-sdk |
| ZK proof system | Groth16 over BN254 |
| Hash function | Poseidon (CAP-0075 params) |
| Circuit language | Circom 2 |
| Browser proving | snarkjs WASM in Web Worker |
| On-chain verification | Native BN254 pairing (CAP-0074) |
| Frontend | TypeScript / React / Vite |
| Wallet | Freighter |
| Oracle | Reflector (SEP-40) |
| Indexer | Node.js + Soroban-RPC events |
| Trusted setup | Powers-of-Tau (Phase-1 reuse) + own Phase-2 ceremony |

---

## License

MIT
