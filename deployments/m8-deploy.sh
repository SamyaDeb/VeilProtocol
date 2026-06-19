#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."

# ── SECURITY §8 gate — no exceptions ─────────────────────────────────────────
echo "=== SECURITY §8 gate ==="

# 1. Ceremony keys present and verified (prod manifest, not dev)
tools/vk-verify/target/release/vk-verify --keys-dir circuit-keys/prod \
    || { echo "FATAL: prod key manifest mismatch"; exit 1; }

# 2. No prod key hash overlaps with any dev key hash
tools/scripts/assert-mainnet-keys.sh \
    || { echo "FATAL: dev keys in prod path"; exit 1; }

# 3. Both audit passes signed
[ -f "audits/pass1-signed.pdf" ] || { echo "FATAL: audit pass 1 missing"; exit 1; }
[ -f "audits/pass2-signed.pdf" ] || { echo "FATAL: audit pass 2 missing"; exit 1; }

# 4. Bug bounty confirmed live
[ "${BUG_BOUNTY_OPEN:-}" = "yes" ] || { echo "FATAL: set BUG_BOUNTY_OPEN=yes"; exit 1; }

# 5. Production key custody confirmed
[ "${ADMIN_MULTISIG:-}" = "yes" ] || { echo "FATAL: set ADMIN_MULTISIG=yes"; exit 1; }
[ "${AUDITOR_HSM:-}" = "yes" ]    || { echo "FATAL: set AUDITOR_HSM=yes"; exit 1; }

# 6. Incident runbook approved
[ -f "docs/RUNBOOK.md" ]            || { echo "FATAL: runbook missing"; exit 1; }
grep -q "# APPROVED" docs/RUNBOOK.md || { echo "FATAL: runbook not approved"; exit 1; }

echo "=== Gate PASSED. Deploying to Stellar mainnet ==="

# ── Deploy ────────────────────────────────────────────────────────────────────
NETWORK="mainnet"
CONFIG="deployments/mainnet.json"
PASSPHRASE=$(jq -r .network_passphrase "${CONFIG}")
RPC=$(jq -r .rpc_url "${CONFIG}")
SECRET="${SECRET:?Set SECRET in env}"
ADMIN="${ADMIN:?Set ADMIN in env}"

INVOKE="stellar contract invoke --network $NETWORK --source-account $SECRET --fee 1000000 --rpc-url $RPC --network-passphrase \"$PASSPHRASE\""
WASM_DIR="contracts/target/wasm32v1-none/release"

echo "--- Building contracts ---"
cargo build --release --target wasm32v1-none \
    --manifest-path contracts/Cargo.toml 2>&1 | grep -E "Compiling|Finished|error"

echo "--- Deploying asp ---"
ASP=$(stellar contract deploy --wasm "$WASM_DIR/asp.wasm" --source-account "$SECRET" --network "$NETWORK" --fee 1000000 --rpc-url "$RPC" --network-passphrase "$PASSPHRASE" 2>/dev/null | tail -1)
echo "asp: $ASP"

echo "--- Deploying veil_core ---"
VEIL_CORE=$(stellar contract deploy --wasm "$WASM_DIR/veil_core.wasm" --source-account "$SECRET" --network "$NETWORK" --fee 1000000 --rpc-url "$RPC" --network-passphrase "$PASSPHRASE" 2>/dev/null | tail -1)
echo "veil_core: $VEIL_CORE"

echo "--- Deploying amm_pool ---"
AMM_POOL=$(stellar contract deploy --wasm "$WASM_DIR/amm_pool.wasm" --source-account "$SECRET" --network "$NETWORK" --fee 1000000 --rpc-url "$RPC" --network-passphrase "$PASSPHRASE" 2>/dev/null | tail -1)
echo "amm_pool: $AMM_POOL"

echo "--- Deploying lending ---"
LENDING=$(stellar contract deploy --wasm "$WASM_DIR/lending.wasm" --source-account "$SECRET" --network "$NETWORK" --fee 1000000 --rpc-url "$RPC" --network-passphrase "$PASSPHRASE" 2>/dev/null | tail -1)
echo "lending: $LENDING"

# Write to mainnet.json
TMP=$(mktemp)
jq ".contracts.veil_core = \"$VEIL_CORE\" | .contracts.asp = \"$ASP\" | .contracts.amm_pool = \"$AMM_POOL\" | .contracts.lending = \"$LENDING\"" "${CONFIG}" > "$TMP"
mv "$TMP" "${CONFIG}"

echo "--- Initializing veil_core ---"
eval "$INVOKE --id $VEIL_CORE -- initialize --admin $ADMIN"

AUDITOR_PK=$(jq -r .auditor.pubkey "${CONFIG}")
if [ "$AUDITOR_PK" == "" ] || [ "$AUDITOR_PK" == "null" ]; then
    echo "FATAL: Auditor pubkey not in config"
    exit 1
fi
eval "$INVOKE --id $VEIL_CORE -- set_auditor_pubkey --admin $ADMIN --pk $AUDITOR_PK"

# Load VKs
tools/scripts/load-vks-mainnet.sh

# Register ASP
eval "$INVOKE --id $VEIL_CORE -- register_module --admin $ADMIN --module $ASP --perms 4"

echo "--- Initializing ASP ---"
APPROVED_ROOT="${APPROVED_ROOT:-0940b26a62ee9259e50a7af202af473e1eec3737e034e17a6e71a2b207feb656}"
BLOCKED_ROOT="${BLOCKED_ROOT:-2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e}"
# VERIFY: `initialize` signature in asp
eval "$INVOKE --id $ASP -- initialize --operator $ADMIN --approved_root $APPROVED_ROOT --blocked_root $BLOCKED_ROOT"

echo "--- Initializing lending ---"
REFLECTOR=$(jq -r .oracle.reflector_contract "${CONFIG}")
LTV_MAX_BPS=$(jq -r .lending.ltv_max_bps "${CONFIG}")
STALENESS=$(jq -r .oracle.staleness_seconds_approx "${CONFIG}")
eval "$INVOKE --id $LENDING -- initialize --admin $ADMIN --core $VEIL_CORE --oracle $REFLECTOR --ltv_max_bps $LTV_MAX_BPS --staleness $STALENESS"
eval "$INVOKE --id $VEIL_CORE -- register_module --admin $ADMIN --module $LENDING --perms 7"

echo "--- Initializing amm_pool ---"
COMM_PK=$(jq -r .amm.committee_pk "${CONFIG}")
if [ "$COMM_PK" == "null" ] || [ "$COMM_PK" == "" ]; then
    COMM_PK="000000000000000000000000000000000000000000000000ab54a98ceb1f0ad2"
fi
BATCH_K=$(jq -r .amm.batch_size_k "${CONFIG}")
eval "$INVOKE --id $AMM_POOL -- initialize --admin $ADMIN --core $VEIL_CORE --committee $ADMIN --comm_pk $COMM_PK --batch_k $BATCH_K"
eval "$INVOKE --id $VEIL_CORE -- register_module --admin $ADMIN --module $AMM_POOL --perms 3"

echo "=== M8 deploy complete ==="
