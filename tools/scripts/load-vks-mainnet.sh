#!/usr/bin/env bash
set -euo pipefail

# tools/scripts/load-vks-mainnet.sh
# Calls init_vk for each circuit using the ceremony vk.bin, referencing contract IDs from mainnet.json.

cd "$(dirname "$0")/../.."

NETWORK="mainnet"
CONFIG="deployments/mainnet.json"
PASSPHRASE=$(jq -r .network_passphrase "${CONFIG}")
RPC=$(jq -r .rpc_url "${CONFIG}")
VEIL_CORE=$(jq -r .contracts.veil_core "${CONFIG}")

if [ -z "$VEIL_CORE" ] || [ "$VEIL_CORE" == "null" ] || [ "$VEIL_CORE" == "" ]; then
    echo "ERROR: veil_core contract ID not found in ${CONFIG}"
    exit 1
fi

ADMIN="${ADMIN:-admin}" # Assuming an admin identity or source account

BASE_CMD="stellar contract invoke --rpc-url ${RPC} --network-passphrase \"${PASSPHRASE}\" --source ${ADMIN} --fee 1000000 --id ${VEIL_CORE} -- init_vk --admin ${ADMIN}"

echo "Loading VKs to mainnet veil_core..."

for CIRCUIT in deposit kyc_credential transfer withdraw swap batch_settle lend settle_or_refund repay; do
    VK_PATH="circuit-keys/prod/vk_${CIRCUIT}.bin"
    if [ -f "$VK_PATH" ]; then
        # Map circuit name to VkId enum case (CamelCase)
        # e.g. settle_or_refund -> SettleOrRefund
        VK_ID=$(echo "$CIRCUIT" | awk -F_ '{for(i=1;i<=NF;i++) $i=toupper(substr($i,1,1)) tolower(substr($i,2))}1' OFS="")
        
        VK_HEX=$(xxd -p -c 1000000 "$VK_PATH" | tr -d '\n')
        echo "Loading $VK_ID from $VK_PATH..."
        
        CMD="${BASE_CMD} --vk_id '{\"${VK_ID}\":[]}' --vk_bytes ${VK_HEX}"
        eval "$CMD"
    else
        echo "Skipping $CIRCUIT, $VK_PATH not found"
    fi
done

echo "VKs loaded successfully."
