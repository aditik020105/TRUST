#!/usr/bin/env bash
# Stops the Fabric network started by start-network.sh in this folder (orderer, peers and the
# chaincode server, including every child process). Ledger data stays in .run/ until you delete it;
# if you delete it, also empty the TRUST database, or reconciliation will report every old event.
set -uo pipefail
RUN="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/.run"

kill_tree() {
  local pid=$1 child
  for child in $(pgrep -P "$pid" 2>/dev/null); do kill_tree "$child"; done
  kill "$pid" 2>/dev/null
}

if [ -f "$RUN/pids" ]; then
  while read -r pid; do kill_tree "$pid"; done < "$RUN/pids"
  rm -f "$RUN/pids"
  sleep 1
  echo "Fabric network stopped."
else
  echo "No running network found."
fi
