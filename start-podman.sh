#!/usr/bin/env bash
set -e

# ==============================================================================
# TRUST Evidence Custody System - Podman Orchestration Script
# ==============================================================================
# Self-contained container launcher with volume isolation (Zero host clutter)
# Usage:
#   ./start-podman.sh start   - Build images, set up pod, volumes, and launch
#   ./start-podman.sh stop    - Stop running pod and containers
#   ./start-podman.sh logs    - Follow live container logs
#   ./start-podman.sh clean   - Tear down containers, pod, volumes, and images
# ==============================================================================

POD_NAME="trust-pod"
BACKEND_IMAGE="trust-backend:latest"
DASHBOARD_IMAGE="trust-dashboard:latest"
BACKEND_CONTAINER="trust-backend-app"
DASHBOARD_CONTAINER="trust-dashboard-app"
VOL_DATA="trust-data"
VOL_STORAGE="trust-storage"

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" >/dev/null 2>&1 && pwd)"
cd "$DIR"

check_podman() {
  if ! command -v podman &> /dev/null; then
    echo "❌ Error: Podman is not installed or not in PATH."
    echo "Please install Podman or use ./start-local.sh to run directly with Node.js."
    exit 1
  fi
}

start_all() {
  check_podman
  echo "🚀 [TRUST] Starting TRUST Platform with Podman..."

  # 1. Create Pod if not exists
  if ! podman pod exists "$POD_NAME" 2>/dev/null; then
    echo "📦 Creating Podman Pod: $POD_NAME (Ports 3000 & 3001)..."
    podman pod create --name "$POD_NAME" -p 3000:3000 -p 3001:3001
  else
    echo "ℹ️  Podman Pod '$POD_NAME' already exists."
  fi

  # 2. Create Isolated Volumes
  if ! podman volume exists "$VOL_DATA" 2>/dev/null; then
    echo "💾 Creating isolated volume for database state: $VOL_DATA..."
    podman volume create "$VOL_DATA"
  fi

  if ! podman volume exists "$VOL_STORAGE" 2>/dev/null; then
    echo "💾 Creating isolated volume for evidence files: $VOL_STORAGE..."
    podman volume create "$VOL_STORAGE"
  fi

  # 3. Build Backend Image
  echo "🔨 Building Backend container image ($BACKEND_IMAGE)..."
  podman build -t "$BACKEND_IMAGE" -f trust-backend/Containerfile trust-backend

  # 4. Build Frontend Image
  echo "🔨 Building Dashboard container image ($DASHBOARD_IMAGE)..."
  podman build -t "$DASHBOARD_IMAGE" -f trust-dashboard/Containerfile trust-dashboard

  # 5. Remove any older containers with the same names
  podman rm -f "$BACKEND_CONTAINER" 2>/dev/null || true
  podman rm -f "$DASHBOARD_CONTAINER" 2>/dev/null || true

  # 6. Run Backend Container in Pod
  echo "🟢 Launching Backend container ($BACKEND_CONTAINER)..."
  podman run -d \
    --pod "$POD_NAME" \
    --name "$BACKEND_CONTAINER" \
    -v "$VOL_DATA:/app/data" \
    -v "$VOL_STORAGE:/app/storage" \
    "$BACKEND_IMAGE"

  # 7. Run Dashboard Container in Pod
  echo "🟢 Launching Dashboard container ($DASHBOARD_CONTAINER)..."
  podman run -d \
    --pod "$POD_NAME" \
    --name "$DASHBOARD_CONTAINER" \
    "$DASHBOARD_IMAGE"

  echo ""
  echo "=========================================================================="
  echo "✅ TRUST Digital Evidence Platform is running successfully in Podman!"
  echo "=========================================================================="
  echo "🌐 Frontend Dashboard: http://localhost:3000"
  echo "🔒 Backend API:        http://localhost:3001/health"
  echo "🛡️  Identity Provider:  Internal Pre-seeded Roles (No external Cloud auth)"
  echo "📦 State Isolation:    Volumes 'trust-data' & 'trust-storage'"
  echo "=========================================================================="
  echo "Use './start-podman.sh logs' to follow output, or './start-podman.sh stop' to pause."
}

stop_all() {
  check_podman
  echo "🛑 Stopping TRUST Pod and containers..."
  podman pod stop "$POD_NAME" 2>/dev/null || echo "Pod already stopped."
  echo "✅ Pod and containers stopped."
}

logs_all() {
  check_podman
  echo "📜 Streaming logs from $POD_NAME (Ctrl+C to exit)..."
  podman pod logs -f "$POD_NAME" 2>/dev/null || podman logs -f "$BACKEND_CONTAINER"
}

clean_all() {
  check_podman
  echo "🧹 Cleaning up TRUST containers, pod, volumes, and images..."
  podman rm -f "$BACKEND_CONTAINER" "$DASHBOARD_CONTAINER" 2>/dev/null || true
  podman pod rm -f "$POD_NAME" 2>/dev/null || true
  podman volume rm -f "$VOL_DATA" "$VOL_STORAGE" 2>/dev/null || true
  podman rmi -f "$BACKEND_IMAGE" "$DASHBOARD_IMAGE" 2>/dev/null || true
  echo "✅ Clean up completed. Zero host traces remaining."
}

case "${1:-start}" in
  start)
    start_all
    ;;
  stop)
    stop_all
    ;;
  logs)
    logs_all
    ;;
  clean)
    clean_all
    ;;
  *)
    echo "Usage: $0 {start|stop|logs|clean}"
    exit 1
    ;;
esac
