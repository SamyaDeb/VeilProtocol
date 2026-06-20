#!/usr/bin/env bash
# Full testnet orchestration: deploys asp + veil_core + amm_pool + lending,
# wires a TEST-RWA token (native XLM SAC — deployer holds a balance so deposit
# token transfers settle), initializes + registers all modules, and writes a
# COMPLETE deployments/testnet.env that every e2e suite consumes.
#
# Idempotent-ish: re-running deploys a fresh stack and overwrites testnet.env.
#
# Usage:
#   SECRET=S... ADMIN=G... bash deployments/testnet-orchestrate.sh
# or rely on the defaults already in deployments/testnet.env:
#   source deployments/testnet.env && bash deployments/testnet-orchestrate.sh

set -euo pipefail
cd "$(dirname "$0")/.."

RPC="${SOROBAN_RPC:-https://soroban-testnet.stellar.org}"
PASSPHRASE="${PASSPHRASE:-Test SDF Network ; September 2015}"
SECRET="${SECRET:?Set SECRET in env}"
ADMIN="${ADMIN:?Set ADMIN in env}"
NETWORK="${NETWORK:-testnet}"
LTV_MAX_BPS="${LTV_MAX_BPS:-7500}"
STALENESS="${STALENESS:-3600}"
REFLECTOR="${REFLECTOR:-CAFJZQWSED6YAWZU3GWRTOCNPPCGBN32L7QV43XX5LZLFTK6JLN34L6}"
AUDITOR_PK="${AUDITOR_PK:-1b408dafebeddf0871388399b1e53bd065fd70f18580be5cdde15d7eb2c52743}"
APPROVED_ROOT="${APPROVED_ROOT:-0940b26a62ee9259e50a7af202af473e1eec3737e034e17a6e71a2b207feb656}"
BLOCKED_ROOT="${BLOCKED_ROOT:-2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e}"

INVOKE="stellar contract invoke --network $NETWORK --source-account $SECRET --fee 1000000"
WASM_DIR="contracts/target/wasm32v1-none/release"

echo "=== Veil Protocol full testnet orchestration ==="
echo "  Network: $NETWORK   Admin: $ADMIN"

# ── 0. TEST-RWA token: use the native XLM SAC (deployer holds XLM) ────────────
echo ""
echo "--- Ensuring TEST-RWA token (native SAC) is deployed ---"
TOKEN=$(stellar contract id asset --asset native --network "$NETWORK")
stellar contract asset deploy --asset native --source-account "$SECRET" --network "$NETWORK" 2>/dev/null || true
echo "token (native SAC): $TOKEN"

# ── 1. Deploy contracts ───────────────────────────────────────────────────────
deploy() {
    stellar contract deploy --wasm "$WASM_DIR/$1.wasm" \
        --source-account "$SECRET" --network "$NETWORK" --fee 1000000 2>/dev/null | tail -1
}
echo ""
echo "--- Deploying contracts ---"
ASP=$(deploy asp);                  echo "asp:         $ASP"
VEIL_CORE=$(deploy veil_core);      echo "veil_core:   $VEIL_CORE"
AMM_POOL=$(deploy amm_pool);        echo "amm_pool:    $AMM_POOL"
LENDING=$(deploy lending);          echo "lending:     $LENDING"
MOCK_ORACLE=$(deploy mock_oracle);  echo "mock_oracle: $MOCK_ORACLE"

# On testnet the oracle is the deployable mock; mainnet uses the real Reflector.
if [ "$NETWORK" != "mainnet" ]; then
    REFLECTOR="$MOCK_ORACLE"
    # Seed a price (100 @ now) so lending reads succeed within the staleness window.
    $INVOKE --id "$MOCK_ORACLE" -- set_price --price 100 --timestamp "$(date +%s)"
    echo "  mock oracle seeded (price=100)"
fi

# ── 2. Initialize ASP ─────────────────────────────────────────────────────────
echo ""
echo "--- Initializing ASP ---"
$INVOKE --id "$ASP" -- initialize --operator "$ADMIN" \
    --approved_root "$APPROVED_ROOT" --blocked_root "$BLOCKED_ROOT"
echo "  asp initialized"

# ── 3. Initialize veil_core + load VKs ────────────────────────────────────────
echo ""
echo "--- Initializing veil_core ---"
$INVOKE --id "$VEIL_CORE" -- initialize --admin "$ADMIN"
$INVOKE --id "$VEIL_CORE" -- set_auditor_pubkey --admin "$ADMIN" --pk "$AUDITOR_PK"

for vk_name in deposit kyc_credential transfer withdraw swap batch_settle lend; do
    case $vk_name in
        deposit)        vk_id='{"Deposit":[]}'      ; f=vk_deposit       ;;
        kyc_credential) vk_id='{"KycCredential":[]}'; f=vk_kyc           ;;
        transfer)       vk_id='{"Transfer":[]}'     ; f=vk_transfer      ;;
        withdraw)       vk_id='{"Withdraw":[]}'     ; f=vk_withdraw      ;;
        swap)           vk_id='{"Swap":[]}'         ; f=vk_swap          ;;
        batch_settle)   vk_id='{"BatchSettle":[]}'  ; f=vk_batch_settle  ;;
        lend)           vk_id='{"Lend":[]}'         ; f=vk_lend          ;;
    esac
    vk_file="circuit-keys/dev/${f}.bin"
    [ -f "$vk_file" ] || { echo "  SKIP $vk_name ($vk_file missing)"; continue; }
    vk_hex=$(xxd -p -c 1000000 "$vk_file" | tr -d '\n')
    $INVOKE --id "$VEIL_CORE" -- init_vk --admin "$ADMIN" --vk_id "$vk_id" --vk_bytes "$vk_hex"
    echo "  init_vk $vk_name: ok"
done

# ── 4. Initialize modules ─────────────────────────────────────────────────────
echo ""
echo "--- Initializing lending + amm_pool ---"
$INVOKE --id "$LENDING" -- initialize --admin "$ADMIN" --core "$VEIL_CORE" \
    --oracle "$REFLECTOR" --ltv_max_bps "$LTV_MAX_BPS" --staleness "$STALENESS"

COMM_PK=000000000000000000000000000000000000000000000000ab54a98ceb1f0ad2
$INVOKE --id "$AMM_POOL" -- initialize --admin "$ADMIN" --core "$VEIL_CORE" \
    --committee "$ADMIN" --comm_pk "$COMM_PK" --batch_k 4

# ── 5. Register modules in veil_core ──────────────────────────────────────────
echo ""
echo "--- Registering modules (asp=4, lending=7, amm=3, admin=1) ---"
$INVOKE --id "$VEIL_CORE" -- register_module --admin "$ADMIN" --module "$ASP"      --perms 4
$INVOKE --id "$VEIL_CORE" -- register_module --admin "$ADMIN" --module "$LENDING"  --perms 7
$INVOKE --id "$VEIL_CORE" -- register_module --admin "$ADMIN" --module "$AMM_POOL" --perms 3
$INVOKE --id "$VEIL_CORE" -- register_module --admin "$ADMIN" --module "$ADMIN"    --perms 1

# ── 6. Write complete env ─────────────────────────────────────────────────────
echo ""
echo "--- Writing deployments/testnet.env ---"
cat > deployments/testnet.env <<EOF
# Generated by testnet-orchestrate.sh at $(date -u)
VEIL_CORE=$VEIL_CORE
ASP=$ASP
AMM_POOL=$AMM_POOL
LENDING=$LENDING
TOKEN=$TOKEN
REFLECTOR=$REFLECTOR
MOCK_ORACLE=${MOCK_ORACLE:-$REFLECTOR}
LTV_MAX_BPS=$LTV_MAX_BPS
STALENESS=$STALENESS
ADMIN=$ADMIN
SOROBAN_RPC=$RPC
NETWORK=$NETWORK
PASSPHRASE="$PASSPHRASE"
SECRET=$SECRET
AUDITOR_PK=$AUDITOR_PK
APPROVED_ROOT=$APPROVED_ROOT
BLOCKED_ROOT=$BLOCKED_ROOT
INDEXER_URL=http://localhost:3001
EOF

echo ""
echo "=== Orchestration complete ==="
cat deployments/testnet.env
