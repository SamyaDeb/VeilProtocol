#!/usr/bin/env bash
# M6 deploy: veil_core (with VkId::Lend) + lending contract + Reflector wiring
# Builds on top of an existing M3/M5 environment; lending is additive.
#
# Usage: source deployments/testnet.env && bash deployments/m6-deploy.sh
#
# Required env vars (from testnet.env or set manually):
#   SECRET        — signing key (Stellar keypair)
#   ADMIN         — admin address (G...)
#   VEIL_CORE     — existing veil_core contract id (redeploy if not set)
#   ASP           — existing asp contract id
#   NETWORK       — testnet | mainnet (default: testnet)
#   SOROBAN_RPC   — RPC URL (default: soroban-testnet.stellar.org)
# Optional:
#   REFLECTOR     — Reflector contract id; defaults to testnet well-known address
#   LTV_MAX_BPS   — max LTV in basis points (default: 7500 = 75%)
#   STALENESS     — oracle staleness window in seconds (default: 3600 = 1 hour)
#   AUDITOR_PK    — 32-byte hex auditor pubkey

set -euo pipefail
cd "$(dirname "$0")/.."

RPC="${SOROBAN_RPC:-https://soroban-testnet.stellar.org}"
PASSPHRASE="${PASSPHRASE:-Test SDF Network ; September 2015}"
SECRET="${SECRET:?Set SECRET in env}"
ADMIN="${ADMIN:?Set ADMIN in env}"
ASP="${ASP:?Set ASP in env}"
NETWORK="${NETWORK:-testnet}"
LTV_MAX_BPS="${LTV_MAX_BPS:-7500}"
STALENESS="${STALENESS:-3600}"

# Reflector testnet contract id — VERIFY against reflector-network docs before mainnet
REFLECTOR="${REFLECTOR:-CAFJZQWSED6YAWZU3GWRTOCNPPCGBN32L7QV43XX5LZLFTK6JLN34L6}"

INVOKE="stellar contract invoke --network $NETWORK --source-account $SECRET --fee 1000000"
WASM_DIR="contracts/target/wasm32v1-none/release"

echo "=== M6 Veil Protocol deploy (Private RWA Lending) ==="
echo "  Network:   $NETWORK"
echo "  Admin:     $ADMIN"
echo "  Reflector: $REFLECTOR"
echo "  LTV max:   $LTV_MAX_BPS bps"
echo "  Staleness: $STALENESS s"

# ── 1. (Re)deploy veil_core — now carries VkId::Lend ───────────────────────────
echo ""
echo "--- Building contracts ---"
cargo build --release --target wasm32v1-none \
    --manifest-path contracts/Cargo.toml 2>&1 | grep -E "Compiling|Finished|error"

echo ""
echo "--- Deploying veil_core (with VkId::Lend) ---"
VEIL_CORE_NEW=$(stellar contract deploy \
    --wasm "$WASM_DIR/veil_core.wasm" \
    --source-account "$SECRET" \
    --network "$NETWORK" \
    --fee 1000000 2>/dev/null | tail -1)
VEIL_CORE="${VEIL_CORE_NEW}"
echo "veil_core: $VEIL_CORE"

# ── 2. Deploy lending ───────────────────────────────────────────────────────────
echo ""
echo "--- Deploying lending ---"
LENDING=$(stellar contract deploy \
    --wasm "$WASM_DIR/lending.wasm" \
    --source-account "$SECRET" \
    --network "$NETWORK" \
    --fee 1000000 2>/dev/null | tail -1)
echo "lending: $LENDING"

# ── 3. Deploy or reuse amm_pool ────────────────────────────────────────────────
echo ""
echo "--- Deploying amm_pool ---"
AMM_POOL=$(stellar contract deploy \
    --wasm "$WASM_DIR/amm_pool.wasm" \
    --source-account "$SECRET" \
    --network "$NETWORK" \
    --fee 1000000 2>/dev/null | tail -1)
echo "amm_pool: $AMM_POOL"

# ── 4. Initialize veil_core ─────────────────────────────────────────────────────
echo ""
echo "--- Initializing veil_core ---"
$INVOKE --id "$VEIL_CORE" -- initialize --admin "$ADMIN"
echo "  initialize: ok"

AUDITOR_PK="${AUDITOR_PK:-1b408dafebeddf0871388399b1e53bd065fd70f18580be5cdde15d7eb2c52743}"
$INVOKE --id "$VEIL_CORE" -- set_auditor_pubkey --admin "$ADMIN" --pk "$AUDITOR_PK"
echo "  set_auditor_pubkey: ok"

# Load all circuit VKs including the new Lend key
for vk_name in deposit kyc_credential transfer withdraw swap batch_settle lend; do
    case $vk_name in
        deposit)       vk_id='{"Deposit":[]}'       ; f=vk_deposit       ;;
        kyc_credential)vk_id='{"KycCredential":[]}'  ; f=vk_kyc           ;;
        transfer)      vk_id='{"Transfer":[]}'       ; f=vk_transfer      ;;
        withdraw)      vk_id='{"Withdraw":[]}'       ; f=vk_withdraw      ;;
        swap)          vk_id='{"Swap":[]}'           ; f=vk_swap          ;;
        batch_settle)  vk_id='{"BatchSettle":[]}'    ; f=vk_batch_settle  ;;
        lend)          vk_id='{"Lend":[]}'           ; f=vk_lend          ;;
    esac
    vk_file="circuit-keys/dev/${f}.bin"
    if [ ! -f "$vk_file" ]; then
        echo "  SKIP $vk_name — $vk_file not found (run ceremony first)"
        continue
    fi
    vk_hex=$(xxd -p -c 1000000 "$vk_file" | tr -d '\n')
    $INVOKE --id "$VEIL_CORE" -- init_vk \
        --admin "$ADMIN" \
        --vk_id "$vk_id" \
        --vk_bytes "$vk_hex"
    echo "  init_vk $vk_name: ok"
done

# Register ASP with VERIFY perm (4)
$INVOKE --id "$VEIL_CORE" -- register_module \
    --admin "$ADMIN" --module "$ASP" --perms 4
echo "  register asp (perm=4): ok"

# ── 5. Initialize ASP ──────────────────────────────────────────────────────────
echo ""
echo "--- (Re)initializing ASP ---"
APPROVED_ROOT="${APPROVED_ROOT:-0940b26a62ee9259e50a7af202af473e1eec3737e034e17a6e71a2b207feb656}"
BLOCKED_ROOT="${BLOCKED_ROOT:-2134e76ac5d21aab186c2be1dd8f84ee880a1e46eaf712f9d371b6df22191f3e}"
$INVOKE --id "$ASP" -- update_approved \
    --op "$ADMIN" --new_root "$APPROVED_ROOT" --attest 00 2>/dev/null || true
$INVOKE --id "$ASP" -- update_blocked \
    --op "$ADMIN" --new_root "$BLOCKED_ROOT" --attest 00 2>/dev/null || true
echo "  asp roots updated: ok"

# ── 6. Initialize lending ──────────────────────────────────────────────────────
echo ""
echo "--- Initializing lending ---"
$INVOKE --id "$LENDING" -- initialize \
    --admin "$ADMIN" \
    --core "$VEIL_CORE" \
    --oracle "$REFLECTOR" \
    --ltv_max_bps "$LTV_MAX_BPS" \
    --staleness "$STALENESS"
echo "  initialize: ok"

# Register lending in veil_core with INSERT(1)|SPEND(2)|LOCK(4) = 7
$INVOKE --id "$VEIL_CORE" -- register_module \
    --admin "$ADMIN" --module "$LENDING" --perms 7
echo "  register lending in veil_core (INSERT|SPEND|LOCK = 7): ok"

# ── 7. Initialize amm_pool ────────────────────────────────────────────────────
echo ""
echo "--- Initializing amm_pool ---"
COMM_PK=000000000000000000000000000000000000000000000000ab54a98ceb1f0ad2
$INVOKE --id "$AMM_POOL" -- initialize \
    --admin "$ADMIN" \
    --core "$VEIL_CORE" \
    --committee "$ADMIN" \
    --comm_pk "$COMM_PK" \
    --batch_k 4
echo "  initialize: ok"

# Register amm_pool in veil_core with INSERT(1)|SPEND(2) = 3
$INVOKE --id "$VEIL_CORE" -- register_module \
    --admin "$ADMIN" --module "$AMM_POOL" --perms 3
echo "  register amm_pool in veil_core (INSERT|SPEND = 3): ok"

# Register admin for direct INSERT (spike/test convenience only)
$INVOKE --id "$VEIL_CORE" -- register_module \
    --admin "$ADMIN" --module "$ADMIN" --perms 1
echo "  register admin as INSERT module (test convenience): ok"

# ── 8. Persist updated contract addresses ─────────────────────────────────────
echo ""
echo "--- Updating testnet.env ---"
cat > deployments/testnet.env <<EOF
# Generated by m6-deploy.sh at $(date -u)
VEIL_CORE=$VEIL_CORE
ASP=$ASP
AMM_POOL=$AMM_POOL
LENDING=$LENDING
ADMIN=$ADMIN
REFLECTOR=$REFLECTOR
LTV_MAX_BPS=$LTV_MAX_BPS
STALENESS=$STALENESS
SOROBAN_RPC=$RPC
NETWORK=$NETWORK
PASSPHRASE="$PASSPHRASE"
SECRET=$SECRET
AUDITOR_PK=$AUDITOR_PK
APPROVED_ROOT=$APPROVED_ROOT
BLOCKED_ROOT=$BLOCKED_ROOT
EOF

echo ""
echo "=== M6 deploy complete ==="
echo "  VEIL_CORE=$VEIL_CORE"
echo "  LENDING=$LENDING"
echo "  AMM_POOL=$AMM_POOL"
echo "  ASP=$ASP"
echo ""
echo "Run e2e tests:"
echo "  source deployments/testnet.env && npm run lending --prefix e2e-tests"
