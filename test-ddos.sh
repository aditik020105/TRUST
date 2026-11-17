#!/usr/bin/env bash
# ==============================================================================
# TRUST Platform - DDoS Protection Attack Simulation Script
# ==============================================================================
# Demonstrates that the backend DDoS protection system mitigates high-volume
# concurrent request floods and keeps the server stable and healthy.
# ==============================================================================

set -uo pipefail

# Configuration
TARGET_URL="${TARGET_URL:-http://localhost:3001}"
ATTACK_ENDPOINT="${ATTACK_ENDPOINT:-$TARGET_URL/api/evidence}"
HEALTH_ENDPOINT="${HEALTH_ENDPOINT:-$TARGET_URL/health}"
PING_ENDPOINT="${PING_ENDPOINT:-$TARGET_URL/ping}"
NUM_REQUESTS="${NUM_REQUESTS:-100}"
ATTACKER_IP="${ATTACKER_IP:-198.51.100.$(( (RANDOM % 200) + 10 ))}"

# Colors
if [ -t 1 ] && [ -z "${NO_COLOR:-}" ]; then
  BOLD="\033[1m"
  GREEN="\033[32m"
  RED="\033[31m"
  YELLOW="\033[33m"
  BLUE="\033[34m"
  CYAN="\033[36m"
  RESET="\033[0m"
else
  BOLD=""
  GREEN=""
  RED=""
  YELLOW=""
  BLUE=""
  CYAN=""
  RESET=""
fi

echo -e "${BOLD}${CYAN}"
echo "======================================================================"
echo "          TRUST Platform - DDoS Attack Simulation & Defense Test      "
echo "======================================================================"
echo -e "${RESET}"
echo -e "Target URL:        ${BOLD}${TARGET_URL}${RESET}"
echo -e "Attack Target:     ${BOLD}${ATTACK_ENDPOINT}${RESET}"
echo -e "Flood Magnitude:   ${BOLD}${NUM_REQUESTS} concurrent requests${RESET}"
if [ -n "$ATTACKER_IP" ]; then
  echo -e "Attacker IP:       ${BOLD}${ATTACKER_IP}${RESET} (simulated via X-Forwarded-For)"
fi
echo -e "Health Endpoint:   ${BOLD}${HEALTH_ENDPOINT}${RESET}"
echo "----------------------------------------------------------------------"

# 1. Pre-flight Check: Ensure backend is reachable
echo -n "Checking backend connectivity... "
PRE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 "$PING_ENDPOINT" 2>/dev/null || echo "000")

if [ "$PRE_STATUS" != "200" ]; then
  # Fallback check on health endpoint
  PRE_STATUS=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 4 "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
fi

if [ "$PRE_STATUS" != "200" ]; then
  echo -e "${RED}[FAILED]${RESET}"
  echo -e "${RED}Error: Backend is not reachable at ${TARGET_URL} (Status: ${PRE_STATUS}).${RESET}"
  echo "Please start the backend before running this simulation:"
  echo "  cd trust-backend && npm run dev"
  echo "  OR ./start-podman.sh start"
  exit 1
fi
echo -e "${GREEN}[ONLINE]${RESET} (HTTP ${PRE_STATUS})"

# 2. Setup Temporary Results Directory
TMP_DIR=$(mktemp -d /tmp/ddos-sim-XXXXXX)
trap 'rm -rf "$TMP_DIR"' EXIT INT TERM

get_time_ms() {
  local ms
  ms=$(date +%s%3N 2>/dev/null || true)
  if [[ "$ms" =~ ^[0-9]+$ ]]; then
    echo "$ms"
  else
    echo "$(( $(date +%s) * 1000 ))"
  fi
}

# 3. Launch Concurrent Request Flood
echo -e "\n${BOLD}[PHASE 1] Launching concurrent flood of ${NUM_REQUESTS} requests...${RESET}"
START_MS=$(get_time_ms)

for i in $(seq 1 "$NUM_REQUESTS"); do
  (
    if [ -n "$ATTACKER_IP" ]; then
      HTTP_CODE=$(curl -s -o "$TMP_DIR/body_${i}.json" -w "%{http_code}" \
        --connect-timeout 5 --max-time 15 \
        -H "X-Forwarded-For: $ATTACKER_IP" \
        "$ATTACK_ENDPOINT" 2>/dev/null || echo "000")
    else
      HTTP_CODE=$(curl -s -o "$TMP_DIR/body_${i}.json" -w "%{http_code}" \
        --connect-timeout 5 --max-time 15 \
        "$ATTACK_ENDPOINT" 2>/dev/null || echo "000")
    fi
    echo "$HTTP_CODE" > "$TMP_DIR/code_${i}.txt"
  ) &
done

# Wait for all background requests to finish
wait

END_MS=$(get_time_ms)
DURATION_MS=$(( END_MS - START_MS ))

echo -e "${GREEN}Flood completed${RESET} (Duration: ~${DURATION_MS} ms)"

# 4. Aggregate & Analyze Responses
cat "$TMP_DIR"/code_*.txt > "$TMP_DIR/all_codes.txt"

COUNT_200=$(grep -c "^200" "$TMP_DIR/all_codes.txt" 2>/dev/null || echo "0")
COUNT_429=$(grep -c "^429" "$TMP_DIR/all_codes.txt" 2>/dev/null || echo "0")
COUNT_200=${COUNT_200:-0}
COUNT_429=${COUNT_429:-0}
COUNT_OTHER=$(( NUM_REQUESTS - COUNT_200 - COUNT_429 ))
if [ "$COUNT_OTHER" -lt 0 ]; then COUNT_OTHER=0; fi

PERCENT_MITIGATED=0
if [ "$NUM_REQUESTS" -gt 0 ]; then
  PERCENT_MITIGATED=$(( (COUNT_429 * 100) / NUM_REQUESTS ))
fi

# 5. Inspect Throttled Response Sample
SAMPLE_429_BODY=""
if [ "$COUNT_429" -gt 0 ]; then
  for i in $(seq 1 "$NUM_REQUESTS"); do
    if [ -f "$TMP_DIR/code_${i}.txt" ] && [ "$(cat "$TMP_DIR/code_${i}.txt")" = "429" ]; then
      SAMPLE_429_BODY=$(cat "$TMP_DIR/body_${i}.json" 2>/dev/null || true)
      break
    fi
  done
fi

# 6. Post-Attack Server Health & Isolation Verification
echo -e "\n${BOLD}[PHASE 2] Verifying server survivability and per-IP isolation...${RESET}"
HEALTH_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 "$HEALTH_ENDPOINT" 2>/dev/null || echo "000")
HEALTH_BODY=$(curl -s --connect-timeout 5 "$HEALTH_ENDPOINT" 2>/dev/null || echo "")

CLEAN_IP="192.168.1.99"
CLEAN_CODE=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 5 \
  -H "X-Forwarded-For: $CLEAN_IP" "$ATTACK_ENDPOINT" 2>/dev/null || echo "000")

# 7. Print Mitigation & Health Report
echo -e "\n${BOLD}${CYAN}======================================================================${RESET}"
echo -e "${BOLD}${CYAN}                  DDoS ATTACK MITIGATION REPORT                       ${RESET}"
echo -e "${BOLD}${CYAN}======================================================================${RESET}"
echo -e "Total Requests Fired:        ${BOLD}${NUM_REQUESTS}${RESET}"
echo -e "Requests Allowed (HTTP 200): ${GREEN}${COUNT_200}${RESET}"
echo -e "Requests Blocked (HTTP 429): ${YELLOW}${COUNT_429}${RESET}"
if [ "$COUNT_OTHER" -gt 0 ]; then
  echo -e "Other Responses:             ${RED}${COUNT_OTHER}${RESET}"
fi
echo -e "Mitigation Rate:             ${BOLD}${PERCENT_MITIGATED}%${RESET}"
echo "----------------------------------------------------------------------"
echo -e "Backend Survivability Check: ${HEALTH_ENDPOINT}"
if [ "$HEALTH_CODE" = "200" ]; then
  echo -e "Server Health Status:        ${GREEN}${BOLD}STABLE & RESPONDING (HTTP 200)${RESET}"
  echo -e "Health Response:             ${HEALTH_BODY}"
else
  echo -e "Server Health Status:        ${RED}${BOLD}UNRESPONSIVE / FAILED (HTTP ${HEALTH_CODE})${RESET}"
fi
echo -e "Clean Client Isolation:      ${CLEAN_IP}"
if [ "$CLEAN_CODE" = "200" ]; then
  echo -e "Legitimate Traffic Status:   ${GREEN}${BOLD}UNBLOCKED (HTTP 200)${RESET} (Zero Cross-IP Impact)"
else
  echo -e "Legitimate Traffic Status:   ${YELLOW}HTTP ${CLEAN_CODE}${RESET}"
fi

if [ -n "$SAMPLE_429_BODY" ]; then
  echo "----------------------------------------------------------------------"
  echo -e "Sample Mitigation Payload (HTTP 429):"
  echo -e "  ${SAMPLE_429_BODY}"
fi

echo -e "${BOLD}${CYAN}======================================================================${RESET}"

# 8. Final Verdict
if [ "$COUNT_429" -gt 0 ] && [ "$HEALTH_CODE" = "200" ]; then
  echo -e "${GREEN}${BOLD}[TEST PASSED] DDoS flood attack was successfully mitigated!${RESET}"
  echo -e "${GREEN}Rate limiter throttled ${COUNT_429}/${NUM_REQUESTS} requests while the backend remained 100% operational.${RESET}\n"
  exit 0
elif [ "$HEALTH_CODE" != "200" ]; then
  echo -e "${RED}${BOLD}[TEST FAILED] Server crashed or became unresponsive during the attack!${RESET}\n"
  exit 1
else
  echo -e "${RED}${BOLD}[TEST FAILED] No requests were throttled. DDoS protection was not triggered.${RESET}\n"
  exit 1
fi
