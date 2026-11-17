#!/usr/bin/env bash
# Brings up the Hyperledger Fabric test network, creates the evidence channel, deploys the
# TRUST chaincode, and prints the backend .env lines for LEDGER_MODE=fabric.
#
# Prerequisites: Docker, and fabric-samples with binaries:
#   curl -sSLO https://raw.githubusercontent.com/hyperledger/fabric/main/scripts/install-fabric.sh
#   chmod +x install-fabric.sh && ./install-fabric.sh docker samples binary
#
# Usage: FABRIC_SAMPLES=~/fabric-samples ./fabric/deploy-test-network.sh
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SAMPLES="${FABRIC_SAMPLES:-$HOME/fabric-samples}"
CHANNEL="${FABRIC_CHANNEL:-evidence-channel}"
CC_NAME="${FABRIC_CHAINCODE:-evidence-contract}"
NET="$SAMPLES/test-network"

[ -d "$NET" ] || { echo "fabric-samples not found at $SAMPLES (set FABRIC_SAMPLES)"; exit 1; }

echo "==> Building chaincode"
(cd "$ROOT/trust-chaincode" && npm run sync-logic && npm install && npm run build)

echo "==> Starting test network and channel '$CHANNEL'"
cd "$NET"
./network.sh down || true
./network.sh up createChannel -c "$CHANNEL" -ca

echo "==> Deploying chaincode '$CC_NAME'"
./network.sh deployCC -c "$CHANNEL" -ccn "$CC_NAME" -ccp "$ROOT/trust-chaincode" -ccl typescript

ORG="$NET/organizations/peerOrganizations/org1.example.com"
cat <<ENV

==> Add these lines to trust-backend/.env:

LEDGER_MODE=fabric
FABRIC_CHANNEL=$CHANNEL
FABRIC_CHAINCODE=$CC_NAME
FABRIC_MSP_ID=Org1MSP
FABRIC_PEER_ENDPOINT=localhost:7051
FABRIC_PEER_HOST_ALIAS=peer0.org1.example.com
FABRIC_TLS_CERT_PATH=$ORG/peers/peer0.org1.example.com/tls/ca.crt
FABRIC_CERT_PATH=$ORG/users/User1@org1.example.com/msp/signcerts
FABRIC_KEY_PATH=$ORG/users/User1@org1.example.com/msp/keystore
ENV
