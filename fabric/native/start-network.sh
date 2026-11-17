#!/usr/bin/env bash
# Runs a real Hyperledger Fabric 2.5 network WITHOUT Docker:
#   1 Raft orderer + 1 peer (Org1MSP) as native processes, channel "evidence-channel",
#   and the TRUST chaincode running as an external service (chaincode-as-a-service).
#
# Prerequisites
#   - Fabric binaries + config for your OS, e.g. for Linux/WSL:
#       curl -sSLO https://github.com/hyperledger/fabric/releases/download/v2.5.12/hyperledger-fabric-linux-amd64-2.5.12.tar.gz
#       mkdir -p ~/fabric && tar xzf hyperledger-fabric-linux-amd64-2.5.12.tar.gz -C ~/fabric
#     (macOS: hyperledger-fabric-darwin-arm64-2.5.12.tar.gz / darwin-amd64)
#   - Node 18+, and `npm install` done in trust-chaincode/
#
# Usage:  FABRIC_HOME=~/fabric ./fabric/native/start-network.sh
# Stop:   ./fabric/native/stop-network.sh        (state is kept in fabric/native/.run until you delete it)
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
FABRIC_HOME="${FABRIC_HOME:-$HOME/fabric}"
BIN="$FABRIC_HOME/bin"
CHANNEL="${FABRIC_CHANNEL:-evidence-channel}"
CC_NAME="${FABRIC_CHAINCODE:-evidence-contract}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_ADDR="${CC_ADDR:-127.0.0.1:9999}"
RUN="$HERE/.run"

[ -x "$BIN/peer" ] || { echo "Fabric binaries not found in $BIN (set FABRIC_HOME)"; exit 1; }
export PATH="$BIN:$PATH"

if [ -f "$RUN/pids" ]; then
  echo "A network seems to be running (fabric/native/.run/pids). Run stop-network.sh first."; exit 1
fi
# Refuse to start on top of something already listening on our ports (e.g. a leftover chaincode server)
for port in 7050 7051 7053 "${CC_ADDR##*:}"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Port $port is already in use. Stop the other network/process first (stop-network.sh)."; exit 1
  fi
done
rm -rf "$RUN" && mkdir -p "$RUN/config" "$RUN/logs"
cp "$HERE/configtx.yaml" "$RUN/"
cp "$FABRIC_HOME/config/orderer.yaml" "$RUN/config/"
# Point the peer at our chaincode-as-a-service builder and turn off Docker-based chaincode
sed -e "s#/opt/hyperledger/ccaas_builder#$HERE/ccaas_builder#" "$FABRIC_HOME/config/core.yaml" > "$RUN/config/core.yaml"

ORD="$RUN/crypto/ordererOrganizations/example.com"
ORG1="$RUN/crypto/peerOrganizations/org1.example.com"
ORD_TLS="$ORD/orderers/orderer.example.com/tls"
PEER_TLS="$ORG1/peers/peer0.org1.example.com/tls"

echo "==> 1/7 Generating certificates (cryptogen)"
cryptogen generate --config "$HERE/crypto-config.yaml" --output "$RUN/crypto" >/dev/null

echo "==> 2/7 Creating channel genesis block for '$CHANNEL'"
configtxgen -configPath "$RUN" -profile EvidenceChannel -channelID "$CHANNEL" -outputBlock "$RUN/$CHANNEL.block" 2>"$RUN/logs/configtxgen.log"

echo "==> 3/7 Starting orderer (127.0.0.1:7050, admin 7053)"
(
  export FABRIC_CFG_PATH="$RUN/config"
  export ORDERER_GENERAL_LISTENADDRESS=127.0.0.1 ORDERER_GENERAL_LISTENPORT=7050
  export ORDERER_GENERAL_LOCALMSPID=OrdererMSP ORDERER_GENERAL_LOCALMSPDIR="$ORD/orderers/orderer.example.com/msp"
  export ORDERER_GENERAL_TLS_ENABLED=true
  export ORDERER_GENERAL_TLS_PRIVATEKEY="$ORD_TLS/server.key" ORDERER_GENERAL_TLS_CERTIFICATE="$ORD_TLS/server.crt" ORDERER_GENERAL_TLS_ROOTCAS="[$ORD_TLS/ca.crt]"
  export ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE="$ORD_TLS/server.crt" ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY="$ORD_TLS/server.key" ORDERER_GENERAL_CLUSTER_ROOTCAS="[$ORD_TLS/ca.crt]"
  export ORDERER_GENERAL_BOOTSTRAPMETHOD=none ORDERER_CHANNELPARTICIPATION_ENABLED=true
  export ORDERER_ADMIN_LISTENADDRESS=127.0.0.1:7053 ORDERER_ADMIN_TLS_ENABLED=true
  export ORDERER_ADMIN_TLS_CERTIFICATE="$ORD_TLS/server.crt" ORDERER_ADMIN_TLS_PRIVATEKEY="$ORD_TLS/server.key"
  export ORDERER_ADMIN_TLS_ROOTCAS="[$ORD_TLS/ca.crt]" ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED=true ORDERER_ADMIN_TLS_CLIENTROOTCAS="[$ORD_TLS/ca.crt]"
  export ORDERER_FILELEDGER_LOCATION="$RUN/data/orderer" ORDERER_CONSENSUS_WALDIR="$RUN/data/orderer/etcdraft/wal" ORDERER_CONSENSUS_SNAPDIR="$RUN/data/orderer/etcdraft/snapshot"
  export ORDERER_OPERATIONS_LISTENADDRESS=127.0.0.1:9443 ORDERER_METRICS_PROVIDER=disabled
  exec orderer
) >"$RUN/logs/orderer.log" 2>&1 &
echo $! >> "$RUN/pids"
sleep 3
osnadmin channel join --channelID "$CHANNEL" --config-block "$RUN/$CHANNEL.block" -o 127.0.0.1:7053 \
  --ca-file "$ORD_TLS/ca.crt" --client-cert "$ORD_TLS/server.crt" --client-key "$ORD_TLS/server.key" >/dev/null

echo "==> 4/7 Starting peer0.org1 (127.0.0.1:7051)"
(
  export FABRIC_CFG_PATH="$RUN/config"
  export CORE_PEER_ID=peer0.org1.example.com CORE_PEER_LOCALMSPID=Org1MSP
  export CORE_PEER_MSPCONFIGPATH="$ORG1/peers/peer0.org1.example.com/msp"
  export CORE_PEER_LISTENADDRESS=127.0.0.1:7051 CORE_PEER_ADDRESS=127.0.0.1:7051
  export CORE_PEER_CHAINCODELISTENADDRESS=127.0.0.1:7052 CORE_PEER_CHAINCODEADDRESS=127.0.0.1:7052
  export CORE_PEER_GOSSIP_BOOTSTRAP=127.0.0.1:7051 CORE_PEER_GOSSIP_EXTERNALENDPOINT=127.0.0.1:7051
  export CORE_PEER_TLS_ENABLED=true CORE_PEER_TLS_CERT_FILE="$PEER_TLS/server.crt" CORE_PEER_TLS_KEY_FILE="$PEER_TLS/server.key" CORE_PEER_TLS_ROOTCERT_FILE="$PEER_TLS/ca.crt"
  export CORE_PEER_FILESYSTEMPATH="$RUN/data/peer0" CORE_LEDGER_SNAPSHOTS_ROOTDIR="$RUN/data/peer0/snapshots"
  export CORE_OPERATIONS_LISTENADDRESS=127.0.0.1:9444 CORE_METRICS_PROVIDER=disabled
  export CORE_VM_ENDPOINT=""
  exec peer node start
) >"$RUN/logs/peer0.log" 2>&1 &
echo $! >> "$RUN/pids"
sleep 4

# Peer CLI as the Org1 admin
export FABRIC_CFG_PATH="$RUN/config"
export CORE_PEER_LOCALMSPID=Org1MSP CORE_PEER_ADDRESS=127.0.0.1:7051 CORE_PEER_TLS_ENABLED=true
export CORE_PEER_TLS_ROOTCERT_FILE="$PEER_TLS/ca.crt" CORE_PEER_MSPCONFIGPATH="$ORG1/users/Admin@org1.example.com/msp"
ORDERER_ARGS=(-o 127.0.0.1:7050 --ordererTLSHostnameOverride orderer.example.com --tls --cafile "$ORD_TLS/ca.crt")

peer channel join -b "$RUN/$CHANNEL.block" 2>"$RUN/logs/join.log"

echo "==> 5/7 Packaging and installing chaincode-as-a-service '$CC_NAME'"
PKG="$RUN/ccpkg" && mkdir -p "$PKG/src"
printf '{"address":"%s","dial_timeout":"10s","tls_required":false}\n' "$CC_ADDR" > "$PKG/src/connection.json"
printf '{"type":"ccaas","label":"%s_%s"}\n' "$CC_NAME" "$CC_VERSION" > "$PKG/metadata.json"
tar -C "$PKG/src" -czf "$PKG/code.tar.gz" connection.json
tar -C "$PKG" -czf "$RUN/$CC_NAME.tar.gz" metadata.json code.tar.gz
peer lifecycle chaincode install "$RUN/$CC_NAME.tar.gz" 2>"$RUN/logs/install.log"
PKG_ID="$(peer lifecycle chaincode calculatepackageid "$RUN/$CC_NAME.tar.gz")"
echo "    package id: $PKG_ID"

echo "==> 6/7 Starting chaincode server on $CC_ADDR"
(cd "$ROOT/trust-chaincode" && npm run build >/dev/null)
(
  cd "$ROOT/trust-chaincode"
  exec npx fabric-chaincode-node server --chaincode-address="$CC_ADDR" --chaincode-id="$PKG_ID"
) >"$RUN/logs/chaincode.log" 2>&1 &
echo $! >> "$RUN/pids"
echo "$PKG_ID" > "$RUN/package-id"
sleep 3

echo "==> 7/7 Approving and committing chaincode definition"
peer lifecycle chaincode approveformyorg "${ORDERER_ARGS[@]}" --channelID "$CHANNEL" --name "$CC_NAME" \
  --version "$CC_VERSION" --package-id "$PKG_ID" --sequence 1 2>"$RUN/logs/approve.log"
peer lifecycle chaincode commit "${ORDERER_ARGS[@]}" --channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" \
  --sequence 1 --peerAddresses 127.0.0.1:7051 --tlsRootCertFiles "$PEER_TLS/ca.crt" 2>"$RUN/logs/commit.log"
peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME" 2>/dev/null | sed 's/^/    /'

cat <<ENV

Fabric network is up. Add these lines to trust-backend/.env and restart the backend:

LEDGER_MODE=fabric
FABRIC_CHANNEL=$CHANNEL
FABRIC_CHAINCODE=$CC_NAME
FABRIC_MSP_ID=Org1MSP
FABRIC_PEER_ENDPOINT=127.0.0.1:7051
FABRIC_PEER_HOST_ALIAS=peer0.org1.example.com
FABRIC_TLS_CERT_PATH=$PEER_TLS/ca.crt
FABRIC_CERT_PATH=$ORG1/users/User1@org1.example.com/msp/signcerts
FABRIC_KEY_PATH=$ORG1/users/User1@org1.example.com/msp/keystore

Logs: $RUN/logs
ENV
