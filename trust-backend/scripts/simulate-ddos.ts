import http from "http"

const TARGET_URL = process.env.TARGET_URL || "http://localhost:3001"
const ATTACK_ENDPOINT = `${TARGET_URL}/api/evidence`
const HEALTH_ENDPOINT = `${TARGET_URL}/health`
const NUM_REQUESTS = Number(process.env.NUM_REQUESTS || 100)
const ATTACKER_IP = `198.51.100.${Math.floor(Math.random() * 200) + 10}`

function sendRequest(url: string, ip: string): Promise<{ status: number; body: string }> {
  return new Promise((resolve) => {
    const u = new URL(url)
    const req = http.request(
      {
        hostname: u.hostname,
        port: u.port,
        path: u.pathname,
        method: "GET",
        headers: {
          "X-Forwarded-For": ip,
          "User-Agent": "DDoS-Simulation-Bot/1.0"
        },
        timeout: 8000
      },
      (res) => {
        let data = ""
        res.on("data", (chunk) => (data += chunk))
        res.on("end", () => resolve({ status: res.statusCode || 0, body: data }))
      }
    )
    req.on("error", (err) => resolve({ status: 0, body: err.message }))
    req.on("timeout", () => {
      req.destroy()
      resolve({ status: 408, body: "Timeout" })
    })
    req.end()
  })
}

async function main() {
  console.log("\n======================================================================")
  console.log("          TRUST Platform - DDoS Attack Simulation & Defense Test      ")
  console.log("======================================================================")
  console.log(`Target URL:        ${TARGET_URL}`)
  console.log(`Attack Target:     ${ATTACK_ENDPOINT}`)
  console.log(`Flood Magnitude:   ${NUM_REQUESTS} concurrent requests`)
  console.log(`Attacker IP:       ${ATTACKER_IP} (simulated via X-Forwarded-For)`)
  console.log(`Health Endpoint:   ${HEALTH_ENDPOINT}`)
  console.log("----------------------------------------------------------------------")

  // 1. Connectivity Check
  process.stdout.write("Checking backend connectivity... ")
  const pre = await sendRequest(HEALTH_ENDPOINT, "127.0.0.1")
  if (pre.status !== 200) {
    console.log(`[FAILED] (HTTP ${pre.status})`)
    console.error(`Error: Backend is not reachable at ${TARGET_URL}`)
    process.exit(1)
  }
  console.log("[ONLINE] (HTTP 200)\n")

  // 2. Launch Flood
  console.log(`[PHASE 1] Launching flood of ${NUM_REQUESTS} concurrent requests...`)
  const start = Date.now()

  const promises: Promise<{ status: number; body: string }>[] = []
  for (let i = 0; i < NUM_REQUESTS; i++) {
    promises.push(sendRequest(ATTACK_ENDPOINT, ATTACKER_IP))
  }

  const results = await Promise.all(promises)
  const duration = Date.now() - start
  console.log(`Flood completed in ${duration} ms\n`)

  // 3. Count Results
  let countAllowed = 0
  let countThrottled = 0
  let countOther = 0
  let sample429 = ""

  for (const r of results) {
    if (r.status === 200 || r.status === 401) {
      // 401 means request reached route handler and asked for auth (allowed through firewall!)
      countAllowed++
    } else if (r.status === 429) {
      countThrottled++
      if (!sample429) sample429 = r.body
    } else {
      countOther++
    }
  }

  // 4. Survivability Check
  console.log("[PHASE 2] Verifying server survivability and legitimate traffic...")
  const postHealth = await sendRequest(HEALTH_ENDPOINT, "127.0.0.1")
  const cleanIp = "192.168.1.99"
  const cleanReq = await sendRequest(ATTACK_ENDPOINT, cleanIp)

  const percentMitigated = Math.round((countThrottled * 100) / NUM_REQUESTS)

  // 5. Report
  console.log("\n======================================================================")
  console.log("                  DDoS ATTACK MITIGATION REPORT                       ")
  console.log("======================================================================")
  console.log(`Total Requests Fired:        ${NUM_REQUESTS}`)
  console.log(`Requests Allowed (HTTP 200): ${countAllowed}`)
  console.log(`Requests Blocked (HTTP 429): ${countThrottled}`)
  if (countOther > 0) console.log(`Other Responses:             ${countOther}`)
  console.log(`Mitigation Rate:             ${percentMitigated}%`)
  console.log("----------------------------------------------------------------------")
  console.log(`Server Health Status:        ${postHealth.status === 200 ? "STABLE & RESPONDING (HTTP 200)" : "FAILED"}`)
  if (postHealth.status === 200) {
    console.log(`Health Response:             ${postHealth.body}`)
  }
  console.log(`Legitimate User (Clean IP):  ${cleanReq.status === 200 || cleanReq.status === 401 ? "UNBLOCKED (Zero Cross-IP Impact)" : "HTTP " + cleanReq.status}`)

  if (sample429) {
    console.log("----------------------------------------------------------------------")
    console.log("Sample Mitigation Payload (HTTP 429):")
    console.log(`  ${sample429.trim()}`)
  }
  console.log("======================================================================\n")

  if (countThrottled > 0 && postHealth.status === 200) {
    console.log("[TEST PASSED] DDoS flood attack was successfully mitigated!")
    console.log(`Rate limiter throttled ${countThrottled}/${NUM_REQUESTS} requests while the backend remained 100% operational.\n`)
    process.exit(0)
  } else {
    console.log("[TEST FAILED] Protection was not triggered or server crashed.\n")
    process.exit(1)
  }
}

main().catch((err) => {
  console.error("Simulation error:", err)
  process.exit(1)
})

