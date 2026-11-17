#!/usr/bin/env bash
set -e

# ==============================================================================
# TRUST Evidence Custody System - Direct Local Execution Script
# ==============================================================================
# Launches backend and dashboard directly using local Node.js environments.
# ==============================================================================

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

echo "🚀 [TRUST] Launching TRUST Platform in Local Development Mode..."

# Check node
if ! command -v node &> /dev/null; then
  echo "❌ Error: Node.js is not installed or not in PATH."
  exit 1
fi

cleanup() {
  echo ""
  echo "🛑 Shutting down TRUST backend and dashboard..."
  if [ -n "$BACKEND_PID" ]; then
    kill "$BACKEND_PID" 2>/dev/null || true
  fi
  if [ -n "$FRONTEND_PID" ]; then
    kill "$FRONTEND_PID" 2>/dev/null || true
  fi
  wait 2>/dev/null || true
  echo "✅ Stopped all processes."
  exit 0
}

trap cleanup SIGINT SIGTERM EXIT

# 1. Start Backend
echo "🟢 Starting TRUST Backend on port 3001..."
(
  cd "$DIR/trust-backend"
  npm run dev
) &
BACKEND_PID=$!

# 2. Start Frontend
echo "🟢 Starting TRUST Dashboard on port 3000..."
(
  cd "$DIR/trust-dashboard"
  npm run dev
) &
FRONTEND_PID=$!

echo ""
echo "=========================================================================="
echo "✅ TRUST System Running Locally!"
echo "=========================================================================="
echo "🌐 Frontend Dashboard: http://localhost:3000"
echo "🔒 Backend API:        http://localhost:3001/health"
echo "=========================================================================="
echo "Press Ctrl+C to stop both servers."

wait
