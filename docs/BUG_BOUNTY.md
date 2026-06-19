# Bug Bounty Program

Veil Protocol offers a bug bounty for vulnerabilities in our mainnet deployment.

## Scope
The following components are in scope:
- All Soroban smart contracts in `contracts/`
- All ZK circuits in `circuits/`
- The `vk-convert` tool in `tools/vk-convert/`
- The `veil_core.verify_groth16` verification path

## Rewards
Rewards are aligned with severity:
- **Critical** (Fund theft, value forgery, double-spend, proof soundness break): Up to $100,000
- **High** (Privacy break, auth bypass, censorship of funds, oracle abuse): Up to $25,000
- **Medium** (Bounded leak, griefing, liveness degrade): Up to $5,000
- **Low/Info** (Hardening, defense-in-depth): Up to $500

## Disclosure Instructions
Please submit all vulnerability reports directly to `security@veilprotocol.com`. Do not disclose vulnerabilities publicly before a fix has been deployed. Allow up to 48 hours for an initial response.
