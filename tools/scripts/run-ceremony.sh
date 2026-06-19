#!/usr/bin/env bash
set -euo pipefail

# tools/scripts/run-ceremony.sh
# Runs the Phase-2 ceremony for a single circuit using snarkjs directly.

USAGE="Usage: $0 --circuit <name> --contributors <n> --r1cs <path> --ptau <path> --out <dir>"

CIRCUIT=""
CONTRIBUTORS=""
R1CS=""
PTAU=""
OUT_DIR=""

while [[ $# -gt 0 ]]; do
  case $1 in
    --circuit) CIRCUIT="$2"; shift 2 ;;
    --contributors) CONTRIBUTORS="$2"; shift 2 ;;
    --r1cs) R1CS="$2"; shift 2 ;;
    --ptau) PTAU="$2"; shift 2 ;;
    --out) OUT_DIR="$2"; shift 2 ;;
    *) echo "Unknown param: $1"; echo "$USAGE"; exit 1 ;;
  esac
done

if [[ -z "$CIRCUIT" || -z "$CONTRIBUTORS" || -z "$R1CS" || -z "$PTAU" || -z "$OUT_DIR" ]]; then
  echo "$USAGE"
  exit 1
fi

mkdir -p "$OUT_DIR"
TRANSCRIPT="circuit-keys/ceremony-transcript.txt"

echo "=== Running ceremony for circuit: $CIRCUIT ==="
echo "Circuit: $CIRCUIT" >> "$TRANSCRIPT"

# 1. snarkjs groth16 setup
echo "Running groth16 setup..."
npx snarkjs groth16 setup "$R1CS" "$PTAU" "$OUT_DIR/${CIRCUIT}_0000.zkey"

# 2. For each contributor: snarkjs zkey contribute
PREV_ZKEY="$OUT_DIR/${CIRCUIT}_0000.zkey"
for (( i=1; i<=CONTRIBUTORS; i++ )); do
  NEXT_ZKEY="$OUT_DIR/${CIRCUIT}_$(printf "%04d" $i).zkey"
  echo "Contribution $i..."
  ENTROPY=$(head -c 32 /dev/urandom | base64)
  # Run contribution and append hash to transcript
  npx snarkjs zkey contribute "$PREV_ZKEY" "$NEXT_ZKEY" --name="Contributor $i" -v -e="$ENTROPY" | grep -i "Contribution Hash" >> "$TRANSCRIPT" || echo "Contribution $i completed" >> "$TRANSCRIPT"
  PREV_ZKEY="$NEXT_ZKEY"
done

FINAL_ZKEY="$OUT_DIR/${CIRCUIT}_final.zkey"
cp "$PREV_ZKEY" "$FINAL_ZKEY"

# 3. snarkjs zkey verify
echo "Verifying final zkey..."
npx snarkjs zkey verify "$R1CS" "$PTAU" "$FINAL_ZKEY"

# 4. snarkjs zkey export verificationkey
echo "Exporting vk.json..."
npx snarkjs zkey export verificationkey "$FINAL_ZKEY" "$OUT_DIR/vk_${CIRCUIT}.json"

# 5. vk-convert
echo "Converting vk.json to vk.bin..."
tools/vk-convert/target/release/vk-convert "$OUT_DIR/vk_${CIRCUIT}.json" "$OUT_DIR/vk_${CIRCUIT}.bin"

echo "=== Ceremony for $CIRCUIT complete ==="
