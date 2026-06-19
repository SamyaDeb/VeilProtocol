#!/usr/bin/env bash
set -euo pipefail

# tools/scripts/update-prod-manifest.sh
# Recompute circuit-keys/prod/manifest.sha256 to add prod entries and append to circuit-keys/manifest.sha256.

cd "$(dirname "$0")/../.."

PROD_DIR="circuit-keys/prod"
DEV_DIR="circuit-keys/dev"

mkdir -p "$PROD_DIR"
touch "circuit-keys/manifest.sha256"
touch "$PROD_DIR/manifest.sha256"

# Create/overwrite prod manifest with just the prod keys
echo "Recomputing $PROD_DIR/manifest.sha256..."
> "$PROD_DIR/manifest.sha256"
for f in "$PROD_DIR"/*.bin; do
    if [ -f "$f" ]; then
        sha256sum "$f" >> "$PROD_DIR/manifest.sha256"
        # also append to root manifest if not already present
        HASH=$(sha256sum "$f" | awk '{print $1}')
        if ! grep -q "$HASH" "circuit-keys/manifest.sha256" 2>/dev/null; then
            sha256sum "$f" >> "circuit-keys/manifest.sha256"
        fi
    fi
done

echo "Updated manifests with prod keys."
