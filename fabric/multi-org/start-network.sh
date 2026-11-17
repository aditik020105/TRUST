#!/usr/bin/env bash
# Multi-organisation Hyperledger Fabric 2.5 network for TRUST, without Docker:
#   - Raft orderer (OrdererMSP)                       127.0.0.1:7050 (admin 7053)
#   - peer0.police.trust.local     (PoliceOrgMSP)      127.0.0.1:7051
#   - peer0.forensics.trust.local  (ForensicsOrgMSP)   127.0.0.1:8051
#   - peer0.judiciary.trust.local  (JudiciaryOrgMSP)   127.0.0.1:9051
#   - AdminOrgMSP: client-only organisation for consortium administrators
#   - channel "evidence-channel", chaincode "evidence-contract" with endorsement policy
#     OutOf(2, Police, Forensics, Judiciary): every transaction must be endorsed by 2 of the 3 agencies
#   - private data collection "evidencePrivateDetails" held only by Police and Judiciary peers
#
# Prerequisites: Fabric 2.5 binaries + config in $FABRIC_HOME (bin/, config/), Node 18+,
# `npm install` in trust-chaincode/.
#   curl -sSLO https://github.com/hyperledger/fabric/releases/download/v2.5.12/hyperledger-fabric-linux-amd64-2.5.12.tar.gz
#   mkdir -p ~/fabric && tar xzf hyperledger-fabric-linux-amd64-2.5.12.tar.gz -C ~/fabric
#
# Usage: FABRIC_HOME=~/fabric ./fabric/multi-org/start-network.sh           Stop: ./fabric/multi-org/stop-network.sh
#   First run creates the network. Later runs RESUME it with the same ledger (e.g. after a reboot).
#   --fresh deletes everything and starts a new, empty ledger (then also empty the TRUST database).
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/../.." && pwd)"
FABRIC_HOME="${FABRIC_HOME:-$HOME/fabric}"
CHANNEL="${FABRIC_CHANNEL:-evidence-channel}"
CC_NAME="${FABRIC_CHAINCODE:-evidence-contract}"
CC_VERSION="${CC_VERSION:-1.0}"
CC_ADDR="${CC_ADDR:-127.0.0.1:9999}"
ENDORSEMENT="OutOf(2,'PoliceOrgMSP.peer','ForensicsOrgMSP.peer','JudiciaryOrgMSP.peer')"
RUN="$HERE/.run"

[ -x "$FABRIC_HOME/bin/peer" ] || { echo "Fabric binaries not found in $FABRIC_HOME/bin (set FABRIC_HOME)"; exit 1; }
export PATH="$FABRIC_HOME/bin:$PATH"
[ -f "$RUN/pids" ] && { echo "Network already running; run stop-network.sh first."; exit 1; }

# Refuse to start on top of something already listening on our ports (e.g. a leftover chaincode server)
for port in 7050 7051 7053 "${CC_ADDR##*:}"; do
  if (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null; then
    echo "Port $port is already in use. Stop the other network/process first (stop-network.sh)."; exit 1
  fi
done
RESUME=0
if [ "${1:-}" != "--fresh" ] && [ -f "$RUN/package-id" ]; then
  RESUME=1
  echo "==> Resuming the existing network and ledger in $RUN (use --fresh to start over)"
  mkdir -p "$RUN/logs"
else
  rm -rf "$RUN" && mkdir -p "$RUN/config" "$RUN/logs"
  cp "$HERE/configtx.yaml" "$RUN/"
  cp "$FABRIC_HOME/config/orderer.yaml" "$RUN/config/"
  sed -e "s#/opt/hyperledger/ccaas_builder#$HERE/ccaas_builder#" "$FABRIC_HOME/config/core.yaml" > "$RUN/config/core.yaml"
fi

CRYPTO="$RUN/crypto"
ORD="$CRYPTO/ordererOrganizations/orderer.trust.local"
ORD_TLS="$ORD/orderers/orderer.orderer.trust.local/tls"
org_dir() { echo "$CRYPTO/peerOrganizations/$1.trust.local"; }
peer_tls() { echo "$(org_dir "$1")/peers/peer0.$1.trust.local/tls"; }

if [ "$RESUME" != 1 ]; then
echo "==> 1/8 Certificates for orderer, police, forensics, judiciary, admin"
cryptogen generate --config "$HERE/crypto-config.yaml" --output "$CRYPTO" >/dev/null

echo "==> 2/8 Channel genesis block"
configtxgen -configPath "$RUN" -profile EvidenceChannel -channelID "$CHANNEL" -outputBlock "$RUN/$CHANNEL.block" 2>"$RUN/logs/configtxgen.log"
fi

echo "==> 3/8 Orderer"
(
  export FABRIC_CFG_PATH="$RUN/config"
  export ORDERER_GENERAL_LISTENADDRESS=127.0.0.1 ORDERER_GENERAL_LISTENPORT=7050
  export ORDERER_GENERAL_LOCALMSPID=OrdererMSP ORDERER_GENERAL_LOCALMSPDIR="$ORD/orderers/orderer.orderer.trust.local/msp"
  export ORDERER_GENERAL_TLS_ENABLED=true ORDERER_GENERAL_TLS_PRIVATEKEY="$ORD_TLS/server.key" ORDERER_GENERAL_TLS_CERTIFICATE="$ORD_TLS/server.crt" ORDERER_GENERAL_TLS_ROOTCAS="[$ORD_TLS/ca.crt]"
  export ORDERER_GENERAL_CLUSTER_CLIENTCERTIFICATE="$ORD_TLS/server.crt" ORDERER_GENERAL_CLUSTER_CLIENTPRIVATEKEY="$ORD_TLS/server.key" ORDERER_GENERAL_CLUSTER_ROOTCAS="[$ORD_TLS/ca.crt]"
  export ORDERER_GENERAL_BOOTSTRAPMETHOD=none ORDERER_CHANNELPARTICIPATION_ENABLED=true
  export ORDERER_ADMIN_LISTENADDRESS=127.0.0.1:7053 ORDERER_ADMIN_TLS_ENABLED=true ORDERER_ADMIN_TLS_CERTIFICATE="$ORD_TLS/server.crt" ORDERER_ADMIN_TLS_PRIVATEKEY="$ORD_TLS/server.key"
  export ORDERER_ADMIN_TLS_ROOTCAS="[$ORD_TLS/ca.crt]" ORDERER_ADMIN_TLS_CLIENTAUTHREQUIRED=true ORDERER_ADMIN_TLS_CLIENTROOTCAS="[$ORD_TLS/ca.crt]"
  export ORDERER_FILELEDGER_LOCATION="$RUN/data/orderer" ORDERER_CONSENSUS_WALDIR="$RUN/data/orderer/wal" ORDERER_CONSENSUS_SNAPDIR="$RUN/data/orderer/snap"
  export ORDERER_OPERATIONS_LISTENADDRESS=127.0.0.1:9443 ORDERER_METRICS_PROVIDER=disabled
  exec orderer
) >"$RUN/logs/orderer.log" 2>&1 &
ORDERER_PID=$!
echo $ORDERER_PID >> "$RUN/pids"
disown $ORDERER_PID 2>/dev/null || true
sleep 3
if [ "$RESUME" != 1 ]; then
osnadmin channel join --channelID "$CHANNEL" --config-block "$RUN/$CHANNEL.block" -o 127.0.0.1:7053 \
  --ca-file "$ORD_TLS/ca.crt" --client-cert "$ORD_TLS/server.crt" --client-key "$ORD_TLS/server.key" >/dev/null
fi

start_peer() { # name msp port opsPort
  local name=$1 msp=$2 port=$3 ops=$4 tls; tls="$(peer_tls "$name")"
  (
    export FABRIC_CFG_PATH="$RUN/config"
    export CORE_PEER_ID="peer0.$name.trust.local" CORE_PEER_LOCALMSPID="$msp"
    export CORE_PEER_MSPCONFIGPATH="$(org_dir "$name")/peers/peer0.$name.trust.local/msp"
    export CORE_PEER_LISTENADDRESS="127.0.0.1:$port" CORE_PEER_ADDRESS="127.0.0.1:$port"
    export CORE_PEER_CHAINCODELISTENADDRESS="127.0.0.1:$((port + 1))" CORE_PEER_CHAINCODEADDRESS="127.0.0.1:$((port + 1))"
    export CORE_PEER_GOSSIP_BOOTSTRAP="127.0.0.1:$port" CORE_PEER_GOSSIP_EXTERNALENDPOINT="127.0.0.1:$port"
    export CORE_PEER_TLS_ENABLED=true CORE_PEER_TLS_CERT_FILE="$tls/server.crt" CORE_PEER_TLS_KEY_FILE="$tls/server.key" CORE_PEER_TLS_ROOTCERT_FILE="$tls/ca.crt"
    export CORE_PEER_FILESYSTEMPATH="$RUN/data/$name" CORE_LEDGER_SNAPSHOTS_ROOTDIR="$RUN/data/$name/snapshots"
    export CORE_OPERATIONS_LISTENADDRESS="127.0.0.1:$ops" CORE_METRICS_PROVIDER=disabled CORE_VM_ENDPOINT=""
    exec peer node start
  ) >"$RUN/logs/peer-$name.log" 2>&1 &
  PEER_PID=$!
  echo $PEER_PID >> "$RUN/pids"
  disown $PEER_PID 2>/dev/null || true
}

echo "==> 4/8 Peers for Police (7051), Forensics (8051), Judiciary (9051)"
start_peer police PoliceOrgMSP 7051 9444
start_peer forensics ForensicsOrgMSP 8051 9445
start_peer judiciary JudiciaryOrgMSP 9051 9446
sleep 5

as_admin() { # name msp port
  export FABRIC_CFG_PATH="$RUN/config" CORE_PEER_TLS_ENABLED=true
  export CORE_PEER_LOCALMSPID="$2" CORE_PEER_ADDRESS="127.0.0.1:$3"
  export CORE_PEER_TLS_ROOTCERT_FILE="$(peer_tls "$1")/ca.crt"
  export CORE_PEER_MSPCONFIGPATH="$(org_dir "$1")/users/Admin@$1.trust.local/msp"
}
ORDERER_ARGS=(-o 127.0.0.1:7050 --ordererTLSHostnameOverride orderer.orderer.trust.local --tls --cafile "$ORD_TLS/ca.crt")
ORGS=("police PoliceOrgMSP 7051" "forensics ForensicsOrgMSP 8051" "judiciary JudiciaryOrgMSP 9051")

if [ "$RESUME" != 1 ]; then
echo "==> 5/8 Joining every peer to '$CHANNEL'"
for o in "${ORGS[@]}"; do set -- $o; as_admin "$1" "$2" "$3"; peer channel join -b "$RUN/$CHANNEL.block" 2>>"$RUN/logs/join.log"; done

echo "==> 6/8 Packaging chaincode-as-a-service and installing on all three peers"
PKG="$RUN/ccpkg" && mkdir -p "$PKG/src"
printf '{"address":"%s","dial_timeout":"10s","tls_required":false}\n' "$CC_ADDR" > "$PKG/src/connection.json"
printf '{"type":"ccaas","label":"%s_%s"}\n' "$CC_NAME" "$CC_VERSION" > "$PKG/metadata.json"
tar -C "$PKG/src" -czf "$PKG/code.tar.gz" connection.json
tar -C "$PKG" -czf "$RUN/$CC_NAME.tar.gz" metadata.json code.tar.gz
for o in "${ORGS[@]}"; do set -- $o; as_admin "$1" "$2" "$3"; peer lifecycle chaincode install "$RUN/$CC_NAME.tar.gz" 2>>"$RUN/logs/install.log"; done
PKG_ID="$(peer lifecycle chaincode calculatepackageid "$RUN/$CC_NAME.tar.gz")"
echo "$PKG_ID" > "$RUN/package-id"

fi
PKG_ID="$(cat "$RUN/package-id")"

echo "==> 7/8 Chaincode server ($CC_ADDR), serving all three peers"
(cd "$ROOT/trust-chaincode" && npm run build >/dev/null)
(cd "$ROOT/trust-chaincode" && exec npx fabric-chaincode-node server --chaincode-address="$CC_ADDR" --chaincode-id="$PKG_ID") >"$RUN/logs/chaincode.log" 2>&1 &
CC_PID=$!
echo $CC_PID >> "$RUN/pids"
disown $CC_PID 2>/dev/null || true
sleep 3

if [ "$RESUME" != 1 ]; then
echo "==> 8/8 Each agency approves; definition committed with endorsement policy $ENDORSEMENT"
CC_ARGS=(--channelID "$CHANNEL" --name "$CC_NAME" --version "$CC_VERSION" --sequence 1 --signature-policy "$ENDORSEMENT" --collections-config "$HERE/collections_config.json")
for o in "${ORGS[@]}"; do
  set -- $o; as_admin "$1" "$2" "$3"
  peer lifecycle chaincode approveformyorg "${ORDERER_ARGS[@]}" "${CC_ARGS[@]}" --package-id "$PKG_ID" 2>>"$RUN/logs/approve.log"
done
as_admin police PoliceOrgMSP 7051
peer lifecycle chaincode commit "${ORDERER_ARGS[@]}" "${CC_ARGS[@]}" \
  --peerAddresses 127.0.0.1:7051 --tlsRootCertFiles "$(peer_tls police)/ca.crt" \
  --peerAddresses 127.0.0.1:8051 --tlsRootCertFiles "$(peer_tls forensics)/ca.crt" \
  --peerAddresses 127.0.0.1:9051 --tlsRootCertFiles "$(peer_tls judiciary)/ca.crt" 2>"$RUN/logs/commit.log"
fi
as_admin police PoliceOrgMSP 7051
peer lifecycle chaincode querycommitted --channelID "$CHANNEL" --name "$CC_NAME" 2>/dev/null | sed 's/^/    /'

# Gateway connection profile for the backend: one client identity per organisation.
user_creds() { echo "\"certPath\": \"$(org_dir "$1")/users/User1@$1.trust.local/msp/signcerts\", \"keyPath\": \"$(org_dir "$1")/users/User1@$1.trust.local/msp/keystore\""; }
cat > "$RUN/gateway-orgs.json" <<JSON
{
  "channel": "$CHANNEL",
  "chaincode": "$CC_NAME",
  "defaultOrg": "PoliceOrgMSP",
  "privateCollectionMembers": ["PoliceOrgMSP", "JudiciaryOrgMSP"],
  "orgs": {
    "PoliceOrgMSP":    { "peerEndpoint": "127.0.0.1:7051", "hostAlias": "peer0.police.trust.local",    "tlsCertPath": "$(peer_tls police)/ca.crt",    $(user_creds police) },
    "ForensicsOrgMSP": { "peerEndpoint": "127.0.0.1:8051", "hostAlias": "peer0.forensics.trust.local", "tlsCertPath": "$(peer_tls forensics)/ca.crt", $(user_creds forensics) },
    "JudiciaryOrgMSP": { "peerEndpoint": "127.0.0.1:9051", "hostAlias": "peer0.judiciary.trust.local", "tlsCertPath": "$(peer_tls judiciary)/ca.crt", $(user_creds judiciary) },
    "AdminOrgMSP":     { "peerEndpoint": "127.0.0.1:9051", "hostAlias": "peer0.judiciary.trust.local", "tlsCertPath": "$(peer_tls judiciary)/ca.crt", $(user_creds admin) }
  }
}
JSON

cat <<ENV

Multi-org Fabric network is up. Add to trust-backend/.env and restart the backend:

LEDGER_MODE=fabric
FABRIC_ORGS_FILE=$RUN/gateway-orgs.json

Logs: $RUN/logs
ENV
