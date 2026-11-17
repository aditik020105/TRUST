import dotenv from "dotenv"
dotenv.config({ quiet: true })

import express from "express"
import cors from "cors"
import evidenceRoutes from "./routes/evidence.routes"
import auditRoutes from "./routes/audit.routes"
import adminRoutes from "./routes/admin.routes"
import caseRoutes from "./routes/case.routes"
import { errorMiddleware } from "./middleware/error.middleware"
import { startHealthCheckJob } from "./jobs/healthCheck.job"
import { ddosMiddleware } from "./middleware/ddos.middleware"
import { checkDatabaseConnection, dbMode } from "./lib/supabase"
import { hyperledgerService } from "./services/hyperledger.service"
import { startReconciliationJob, runReconciliation } from "./services/reconciliation.service"
import { firebaseEnabled } from "./services/auth.service"
import { startOutboxWorker } from "./services/audit-row.service"
import { firewallStoreKind } from "./middleware/ddos.middleware"

const app = express()
const PORT = Number(process.env.PORT ?? 3001)

if (process.env.TRUST_PROXY === "true") app.set("trust proxy", 1)
app.disable("x-powered-by")

const defaultOrigins = ["http://localhost:3000", "http://127.0.0.1:3000"]
const allowedOrigins = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim()).filter(Boolean)

// Request pipeline (paper Table VIII): 1 headers/CORS -> 2 firewall -> 3 identity -> 4 policy -> 5 controllers -> 6 ledger
app.use(cors({
  origin: allowedOrigins.length ? allowedOrigins : defaultOrigins,
  credentials: true,
  methods: ["GET", "POST", "PATCH", "OPTIONS"],
  allowedHeaders: ["Content-Type", "Authorization"],
  exposedHeaders: [
    "Content-Disposition",
    "X-OPA-Decision",
    "X-OPA-Rule",
    "X-RateLimit-Limit",
    "X-RateLimit-Remaining",
    "X-RateLimit-Reset",
    "Retry-After",
    "X-DDoS-Protection",
    "X-Evidence-SHA256",
    "X-Ledger-Tx"
  ]
}))
app.use((_req, res, next) => {
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("Referrer-Policy", "no-referrer")
  res.setHeader("X-Frame-Options", "DENY")
  next()
})
app.use(ddosMiddleware)
app.use(express.json({ limit: "2mb" }))

app.get("/health", async (_req, res) => {
  const ledger = await hyperledgerService.info().catch(() => null)
  res.json({ success: true, message: "TRUST backend is running", database: dbMode, ledger: ledger?.mode, firebase: firebaseEnabled(), firewallStore: firewallStoreKind() })
})
app.get("/ping", (_req, res) => {
  res.status(200).send("OK")
})

app.use("/api/evidence", evidenceRoutes)
app.use("/api/audit-log", auditRoutes)
app.use("/api/cases", caseRoutes)
app.use("/api", adminRoutes)

app.use(errorMiddleware)

let server: any
if (process.env.NODE_ENV !== "test") {
  ;(async () => {
    const db = await checkDatabaseConnection()
    console.log(`[startup] database: ${db.mode}${db.ok ? "" : " (PROBLEMS)"}`)
    for (const p of db.problems) console.error(`[startup]   ${p}`)
    const ledger = await hyperledgerService.info()
    console.log(`[startup] ledger: ${ledger.mode} (${ledger.channel}/${ledger.chaincode}) ${ledger.endpoint || ""}`)
    console.log(`[startup] firebase ID-token verification: ${firebaseEnabled() ? "on" : "off (DID signature only)"}`)
    console.log(`[startup] firewall state: ${firewallStoreKind()}${firewallStoreKind() === "memory" ? " (set REDIS_URL to share across instances)" : ""}`)

    server = app.listen(PORT, () => {
      console.log(`Server running on port ${PORT}`)
      if (process.env.SELF_URL && !/localhost|127\.0\.0\.1/.test(process.env.SELF_URL)) startHealthCheckJob()
      startReconciliationJob()
      startOutboxWorker()
      runReconciliation().catch(() => undefined)
    })
    // Slow-request (slowloris) protection
    server.requestTimeout = Number(process.env.REQUEST_TIMEOUT_MS || 15000)
    server.headersTimeout = Math.min(10000, server.requestTimeout) // headers must arrive within 10 s
    server.keepAliveTimeout = 5000
  })().catch(err => {
    console.error("[startup] fatal:", err)
    process.exit(1)
  })
}

export { app, server }
