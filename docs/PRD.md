# PRD — Veil Protocol

## 1. Problem

Stellar hosts **$2B+ in tokenized real-world assets** (Franklin Templeton BENJI,
Ondo, Centrifuge, Etherfuse) and live public RWA lending (Templar, Blend). Every
position, balance, counterparty, and trade on these venues is **fully public**.
For regulated institutions, public-by-default settlement is a non-starter: it
leaks treasury strategy, counterparty relationships, and position sizes to
competitors, and it cannot satisfy client-confidentiality obligations.

SDF's stated north star (CPO Tomer Weller, Meridian 2025) is **"100% private
settlement for institutions."** Protocol 25 "X-Ray" (live, Jan 2026) shipped the
*primitives* to get there — native BN254 (CAP-0074) and Poseidon (CAP-0075) host
functions — but primitives are not privacy. **No private DeFi exists on Stellar
yet.** That gap is the product.

## 2. What we are building

**Veil Protocol** — one shielded-state protocol exposing three products that
share a single Merkle commitment tree, nullifier sets, and Groth16 verifier:

- **Module 1 — Fully-Shielded AMM.** Private swaps where trade size, asset,
  counterparty, balances, *and pool reserves* are hidden, via a batch-auction
  matching engine with encrypted order flow and a threshold-decryption committee.
- **Module 2 — Private RWA Lending.** Borrow against shielded RWA collateral;
  loan-to-value is proven in zero-knowledge as a range proof against a public
  Reflector oracle price, without revealing collateral amount or borrow amount.
- **Module 3 — ZK Compliance.** KYC-gated entry: every deposit must first prove
  membership in an Association Set Provider (ASP) approved set and
  non-membership in a blocked set. Auditor **view keys** allow selective,
  per-position regulatory disclosure without weakening privacy for everyone else.

## 3. Users

| User | Need | What Veil gives them |
|------|------|----------------------|
| **Institutional treasury / fund** | Move and trade tokenized RWAs without leaking strategy or positions | Shielded balances, private swaps, private collateralized borrowing |
| **Compliance officer (at the institution)** | Prove only vetted, sanctioned-screened funds enter the pool | ASP-gated deposits; membership proofs |
| **Regulator / external auditor** | Inspect specific positions on lawful request | View keys decrypt only the notes in scope; no global de-anonymization |
| **ASP operator** | Maintain approved/blocked sets as a compliance service | `asp` contract with governed set updates |
| **Liquidity provider** | Earn fees without exposing LP size/strategy | Shielded LP positions in the batch-auction pool |
| **Protocol/dev integrator** | Build on a shielded-state primitive | Universal note format usable across modules |

Non-users / explicitly not served: retail mixing/anonymity-maximalist use,
sanctioned entities (ASP excludes them by design), users seeking network-level
(IP) anonymity (out of scope — see THREAT_MODEL).

## 4. SDF / market evidence

- Protocol 25 X-Ray shipped native BN254 + Poseidon → Stellar *chose* to invest
  in ZK infrastructure. Veil is the application layer that investment enables.
- SDF north star: "100% private settlement for institutions."
- $2B+ RWAs on Stellar; public-only lending today → unmet private-DeFi demand.
- Nethermind open-sourced SPP (Feb 2026) → ecosystem validation of the
  shielded-pool primitive; Veil productizes it into DeFi + compliance.
- Reflector + RedStone live on mainnet → oracle dependency is already satisfied.

## 5. Scope

### IN (funded program — all three modules; see ROADMAP for sequencing)
- `veil_core`: shared Merkle tree, spent + locked nullifier sets, Groth16 verify
  wrapper, auditor-encrypted note store.
- `asp`: approved (membership) + blocked (non-membership) trees; deposit gating.
- `viewkey`: auditor keypair, per-commitment ciphertext store, selective decrypt.
- Module 1 fully-shielded batch-auction AMM with encrypted reserves +
  threshold-decryption committee.
- Module 2 private lending with ZK LTV range proof vs Reflector oracle.
- Browser WASM prover, Freighter wallet, localStorage note store, swap/lend/
  auditor UIs.
- Node.js indexer that persists the Merkle tree (Soroban RPC keeps ~7 days only).
- Phase-1-reuse + own-Phase-2 trusted setup; multi-party ceremony before mainnet.
- Target asset: Franklin Templeton **BENJI** + **Reflector** oracle; self-issued
  **TEST-RWA** token on testnet as the development fallback.

### OUT (explicitly not in this program)
- **Network-level anonymity** (Tor/mixnet/IP privacy) — documented as user's
  responsibility; relayer mitigates on-chain payer linkage only.
- **Cross-chain / bridge privacy.**
- **MEV-resistance guarantees** beyond what batch auctions inherently provide.
- **Decentralizing the threshold-decryption committee to permissionless** — MVP
  ships a known, reputable committee; permissionless DKG is a later milestone.
- **Permissionless ASP governance** — MVP ASP is operated by a vetted provider.
- **Mobile apps, fiat on/off-ramp, yield strategies, governance token.**
- **Generalized programmable shielded contracts** — three fixed modules only.

## 6. Success metrics

| Metric | Target |
|--------|--------|
| Mainnet shielded deposit→swap→withdraw round-trip | works, ASP-gated, < user-acceptable latency |
| Anonymity set (commitments in pool) at 6 months post-mainnet | growth trend, no de-anon incident |
| Browser proof generation time (swap) | within interactive budget on commodity laptop (target documented in TEST_PLAN) |
| On-chain Groth16 verify cost | within Soroban resource limits with margin |
| Audit outcome | zero unresolved Critical/High at mainnet; Audit Bank sign-off |
| Auditor view-key disclosure | regulator can decrypt exactly the in-scope notes, nothing else |
| RWA integration | ≥1 real issuer asset (BENJI) live on mainnet |

## 7. User stories (with acceptance criteria)

> Each story is testable end-to-end; the binding verification command lives in
> TEST_PLAN.md. ACs use Given/When/Then.

### US-1 — Compliant shielded deposit
- **Given** an institution holding a vetted RWA token,
- **When** they deposit into Veil,
- **Then** the deposit succeeds **only if** an ASP proof shows membership in the
  approved set and non-membership in the blocked set; a commitment is inserted;
  and an auditor ciphertext is stored alongside it.
- **AC:** deposit by a non-approved address is rejected on-chain; an approved
  deposit yields a spendable note and a decryptable-by-auditor ciphertext.

### US-2 — Private swap
- **Given** a user holding a shielded note,
- **When** they submit a swap into a batch,
- **Then** their input note is nullified (added to `spent`), an output note for
  the received asset is created, and **no observer can learn** the trader, size,
  or pre/post balances; only aggregate batch flow is revealed to the committee.
- **AC:** circuit rejects an input note present in `spent` OR `locked`;
  `sum_in = sum_out + public_amount` holds; two distinct swaps in one batch are
  unlinkable to specific traders on-chain.

### US-3 — Private RWA-collateralized borrow
- **Given** a user holding a shielded RWA note,
- **When** they open a loan,
- **Then** the collateral note is added to `locked` (not `spent`), a borrow note
  is minted, and a ZK proof shows `borrow_value ≤ LTV_max × collateral_value`
  using a public oracle price **without revealing either amount**.
- **AC:** loan exceeding LTV is rejected by the circuit; locked collateral cannot
  be swapped or re-borrowed (present in `locked`); repayment moves the nullifier
  from `locked` and releases collateral.

### US-4 — Note portability across modules
- **Given** an output note from a Module-1 swap,
- **When** the user uses it as Module-2 collateral,
- **Then** it works with **no conversion** — same commitment format, same tree.
- **AC:** a swap-output note opens a loan directly in an e2e test.

### US-5 — Auditor selective disclosure
- **Given** a regulator with a valid view key and a lawful scope,
- **When** they request disclosure of a position,
- **Then** they decrypt exactly the in-scope note ciphertext(s) and learn
  amount/asset/owner for those, and nothing about other users.
- **AC:** view key decrypts in-scope notes; attempting other notes yields
  nothing; disclosure is logged.

### US-6 — Liquidity provision (shielded)
- **Given** an LP with shielded assets,
- **When** they add liquidity to the batch-auction pool,
- **Then** their LP position size is hidden while still earning pro-rata fees.
- **AC:** LP can add/remove without revealing position size on-chain; fee accrual
  is provable to the LP.

### US-7 — Tree persistence / recovery
- **Given** Soroban RPC retains only ~7 days of events,
- **When** the indexer restarts or a client syncs from scratch,
- **Then** the full Merkle tree is reconstructed from persisted indexer state and
  matches the on-chain root.
- **AC:** indexer-reconstructed root == on-chain root after a cold start.

## 8. Assumptions & dependencies
- BN254 + Poseidon host-fn signatures are stable as shipped in Protocol 25.
- Reflector remains live and SEP-40 compatible on mainnet.
- A reputable threshold-decryption committee can be assembled for Module 1.
- The Audit Bank funds at least one Soroban audit + one circuit audit.
- Franklin Templeton / issuer cooperation for mainnet BENJI; TEST-RWA covers
  testnet so development is never blocked on issuer timelines.
