#!/usr/bin/env bash
# assert-mainnet-keys.sh — M7 Phase 3C mainnet key gate
#
# Enforces that the mainnet deployment is NOT using dev (solo-ceremony) keys.
# Called from CI before any mainnet deploy step.
#
# Checks:
#   1. circuit-keys/prod/manifest.sha256 exists (prod manifest committed).
#   2. circuit-keys/prod/ contains at least one *_final.zkey (actual prod keys).
#   3. No prod key hash matches any dev key hash (dev keys not promoted to prod).
#   4. vk-verify exits 0 against the prod manifest.
#
# Exit 0  → prod keys present and verified; safe to deploy.
# Exit 1  → gate fails; deployment MUST be aborted.
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
KEYS_DEV="${REPO_ROOT}/circuit-keys/dev"
KEYS_PROD="${REPO_ROOT}/circuit-keys/prod"
PROD_MANIFEST="${KEYS_PROD}/manifest.sha256"
VK_VERIFY="${REPO_ROOT}/tools/vk-verify/target/release/vk-verify"

# ── 1. Prod manifest must exist ───────────────────────────────────────────────
if [[ ! -f "${PROD_MANIFEST}" ]]; then
    echo "ERROR: ${PROD_MANIFEST} not found."
    echo "       The mainnet ceremony has not been completed."
    echo "       DO NOT deploy to mainnet until all Phase-2 contributions are pinned."
    exit 1
fi

# ── 2. At least one prod *_final.zkey must exist ──────────────────────────────
if ! ls "${KEYS_PROD}"/*_final.zkey &>/dev/null; then
    echo "ERROR: No *_final.zkey found in ${KEYS_PROD}/."
    echo "       Run the Phase-2 ceremony and commit the output before deploying."
    exit 1
fi

# ── 3. No prod key hash may match any dev key hash ───────────────────────────
if [[ -f "${KEYS_DEV}/manifest.sha256" ]]; then
    # Extract all hex digests from the dev manifest
    dev_hashes=$(awk '{print $1}' "${KEYS_DEV}/manifest.sha256" | sort)
    # Extract all hex digests from the prod manifest
    prod_hashes=$(awk '{print $1}' "${PROD_MANIFEST}" | sort)
    # Any intersection = a dev key was promoted to prod
    overlap=$(comm -12 <(echo "$dev_hashes") <(echo "$prod_hashes") || true)
    if [[ -n "${overlap}" ]]; then
        echo "ERROR: Dev key hash(es) found in the prod manifest:"
        echo "${overlap}"
        echo "       The solo-dev ceremony keys MUST NOT be used on mainnet."
        echo "       Run a full multi-party Phase-2 ceremony and re-pin."
        exit 1
    fi
fi

# ── 4. vk-verify must pass against the prod manifest ─────────────────────────
if [[ ! -x "${VK_VERIFY}" ]]; then
    echo "ERROR: ${VK_VERIFY} not found or not executable."
    echo "       Run: cargo build --release (in tools/vk-verify/) first."
    exit 1
fi

echo "Verifying prod key integrity with vk-verify..."
if ! "${VK_VERIFY}" --keys-dir "${KEYS_PROD}"; then
    echo "ERROR: vk-verify FAILED on prod keys — manifest mismatch."
    exit 1
fi

echo ""
echo "OK: Mainnet key gate passed — prod keys present, distinct from dev, and verified."
