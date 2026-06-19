# SCF PROPOSAL — Veil Protocol

**Track:** Open (Soroban / smart-contract application).
**Award:** Build Award, four tranches (10% / 20% / 30% / 40%, SCF v7.0).
**Audit:** Soroban Audit Bank (contract + ZK-circuit passes).

## One-paragraph pitch
Veil Protocol is the first privacy-preserving DeFi protocol on Stellar: one
shielded-state core, built on Protocol 25's native BN254 (CAP-0074) and Poseidon
(CAP-0075) host functions, that exposes a fully-shielded AMM, private RWA lending,
and ZK compliance over a single Merkle commitment tree and nullifier set.
Institutions can deposit vetted assets through an Association-Set-Provider gate,
swap and borrow against tokenized RWAs (starting with Franklin Templeton's BENJI,
priced via Reflector) with amounts, balances, and counterparties hidden, and give
regulators auditor "view keys" for lawful, per-position disclosure. Stellar has
$2B+ in tokenized RWAs and only *public* DeFi to use them in; Veil is the private
settlement layer SDF has publicly called its north star — "100% private
settlement for institutions."

## Why fund this (evidence)
- **Stellar already invested in the primitives.** Protocol 25 "X-Ray" shipped
  native BN254 + Poseidon specifically to enable compliance-forward, privacy-
  preserving apps. Veil is the application layer that turns that investment into a
  product. (developers.stellar.org/docs/build/apps/zk; CAP-0074/0075.)
- **Clear, large, unserved market.** $2B+ RWAs (Franklin Templeton, Ondo,
  Centrifuge, Etherfuse); public RWA lending exists (Templar, Blend); **no private
  DeFi exists.** Institutions cannot use public-by-default rails for confidential
  treasury operations. That gap is the product.
- **Direct line to SDF strategy.** SDF's stated north star is institutional
  private settlement. Veil is a concrete, compliance-first realization.
- **De-risked by prior art.** Nethermind's open-source Stellar Private Payments
  proves the shielded-pool primitive on Soroban; we reuse its proven structure
  (circuits, ceremony tooling, ASP design) and extend it into DeFi + compliance,
  rather than starting from zero.
- **Compliance-first, not privacy-maximalist.** Mandatory ASP entry gate +
  auditor view keys make this acceptable to regulated institutions — the opposite
  of an anonymity tool. This is the practical Privacy-Pools equilibrium applied to
  Stellar RWAs.

## Scope & honest feasibility statement
This proposal funds the **fully-shielded** product: an AMM where even pool
reserves are encrypted (via a threshold-decryption committee over batch
auctions), plus private lending and ZK compliance. **We are explicit that a
fully-shielded AMM is research-grade** — there is no production reference for
encrypted-reserve AMMs on any L1 — and we budget **~28–40 weeks** for a single
developer accordingly, with an early de-risking spike (Milestone M3, in Tranche 2)
that validates the committee/clearing design *before* the bulk of AMM work is
committed. We also pre-commit a **public fallback**: if the spike shows the
fully-shielded design is infeasible within budget, we ship a shielded-swap-vs-
public-pool AMM for mainnet and reclassify encrypted reserves as post-grant R&D —
still delivering a first-of-its-kind private-payments + private-lending protocol
on Stellar. We would rather state this risk up front than overclaim at the audit
gate. (Full detail: ROADMAP.md fallbacks; THREAT_MODEL §1.4, §6.)

## Tranche-mapped deliverables
(Each tranche releases on its exit demo's verification command passing —
TEST_PLAN.md. Full milestone detail in ROADMAP.md.)

| Tranche | % | Deliverable (testnet unless noted) | Proof of completion |
|---------|---|------------------------------------|---------------------|
| **T1** | 10% | ShieldCore + ASP-gated deposit + view-key ciphertext (M0); shielded transfer (M1) | `veil e2e deposit`, `veil e2e transfer` green |
| **T2** | 20% | Shielded withdraw + auditor disclosure (M2); fully-shielded AMM de-risk spike, K=4 mock committee (M3) | `veil e2e withdraw-and-audit`, `veil e2e amm-spike` green |
| **T3** | 30% | Encrypted-reserve batch-auction clearing (M4); shielded LP + note portability (M5) | `veil e2e amm-settle`, `veil e2e amm-lp` green |
| **T4** | 40% | Private RWA lending (M6); mainnet ceremony + dual audit remediation (M7); **mainnet launch with BENJI + Reflector** (M8) | `veil e2e lending`, audit sign-off, `veil e2e mainnet-roundtrip --network mainnet` |

## Budget (single developer, ~28–40 weeks)
> Figures are placeholders to be set to SCF norms; structure is what matters.
- **Engineering (protocol):** ~28–40 wk of senior protocol+ZK dev — the bulk.
- **Threshold-decryption committee bring-up:** tooling + initial reputable
  members (Module 1's central new dependency).
- **Audits (Audit Bank):** one Soroban contract audit + one ZK-circuit/setup
  audit; second lending-focused pass before lending hits mainnet.
- **Trusted-setup ceremony:** multi-party Phase-2 coordination + transcript
  publication.
- **Infra:** indexer + optional relayer hosting; testnet/mainnet ops; monitoring.
- **Bug bounty:** funded pool live before mainnet.

## Team & open-source
Single lead developer (protocol architect + ZK + Soroban). All circuits,
contracts, ceremony transcripts, and the indexer are open-sourced, mirroring
SPP's layout, with pinned + hash-verified circuit keys. We credit and build on
Nethermind SPP, Reflector, and the Stellar ZK stack.

## What success looks like
A regulated institution deposits BENJI through a compliance gate, swaps and
borrows against it on Stellar mainnet with amounts and counterparties private,
and a regulator can audit a specific position on lawful request — none of which is
possible on Stellar (or arguably any chain) today. That is "100% private
settlement for institutions," shipped.
