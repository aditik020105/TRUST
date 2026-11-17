/**
 * Measures API latency, ledger commit time and throughput.
 *
 *   npm run bench                         -> isolated temp DB/storage/ledger (local mode)
 *   BENCH_USE_ENV=true npm run bench      -> uses your .env (Supabase and/or Fabric); creates test
 *                                            users and evidence in that database, so use a test project
 *   BENCH_LEDGER=fabric npm run bench    -> isolated DB, live Fabric network from FABRIC_* env vars
 *   BENCH_ITERATIONS=50 BENCH_CONCURRENCY=20 BENCH_FILE_KB=1024 npm run bench
 *
 * Results: printed as a table and saved to bench-results/<timestamp>.json and .md
 */
import fs from "fs"
import os from "os"
import path from "path"
import crypto from "crypto"

if (process.env.BENCH_USE_ENV === "true") {
  require("dotenv").config({ quiet: true })
} else {
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "trust-bench-"))
  process.env.DATA_DIR = path.join(tmp, "data")
  process.env.STORAGE_DIR = path.join(tmp, "storage")
  delete process.env.SUPABASE_URL
  delete process.env.SUPABASE_SERVICE_KEY
  // BENCH_LEDGER=fabric keeps an isolated DB but commits to the Fabric network in FABRIC_* env vars
  if (process.env.BENCH_LEDGER === "fabric") process.env.LEDGER_MODE = "fabric"
  else delete process.env.LEDGER_MODE
  process.env.EVIDENCE_ENCRYPTION_KEY = crypto.randomBytes(32).toString("hex")
}
process.env.NODE_ENV = "test" // do not auto-listen; we start our own server
process.env.TRUST_PROXY = "true" // spread load over fake client IPs so the firewall does not throttle the benchmark
process.env.RECONCILE_CRON = "off"
delete process.env.FIREBASE_PROJECT_ID

// eslint-disable-next-line @typescript-eslint/no-var-requires
const { app } = require("../src/index")
const { userService } = require("../src/services/user.service")
const { generateEd25519KeyPair, signWithPrivateKeyPem, signingPayloads } = require("../src/services/did.service")
const { hyperledgerService } = require("../src/services/hyperledger.service")
const { dbMode } = require("../src/lib/supabase")

const ITER = Number(process.env.BENCH_ITERATIONS || 30)
const CONC = Number(process.env.BENCH_CONCURRENCY || 10)
const FILE_KB = Number(process.env.BENCH_FILE_KB || 256)

type Stat = { name: string; n: number; mean: number; p50: number; p95: number; min: number; max: number }

function stats(name: string, ms: number[]): Stat {
  const s = [...ms].sort((a, b) => a - b)
  const q = (p: number) => s[Math.min(s.length - 1, Math.floor(p * s.length))]
  return { name, n: s.length, mean: s.reduce((a, b) => a + b, 0) / s.length, p50: q(0.5), p95: q(0.95), min: s[0], max: s[s.length - 1] }
}

let ipCounter = 0
const nextIp = () => `10.${(ipCounter >> 16) & 255}.${(ipCounter >> 8) & 255}.${ipCounter++ & 255}`

async function main() {
  const server = app.listen(0)
  const base = `http://127.0.0.1:${(server.address() as any).port}`
  const call = async (method: string, url: string, opts: { token?: string; json?: any; form?: FormData } = {}) => {
    const headers: Record<string, string> = { "X-Forwarded-For": nextIp() }
    if (opts.token) headers.Authorization = `Bearer ${opts.token}`
    let body: any
    if (opts.json) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.json) }
    if (opts.form) body = opts.form
    const t = performance.now()
    const res = await fetch(base + url, { method, headers, body })
    const buf = Buffer.from(await res.arrayBuffer())
    const ms = performance.now() - t
    if (res.status >= 400) throw new Error(`${method} ${url} -> ${res.status} ${buf.toString().slice(0, 200)}`)
    return { ms, res, buf }
  }

  const stamp = Date.now()
  const mk = async (role: string) => {
    const k = generateEd25519KeyPair()
    const u = await userService.registerUser({ email: `bench.${role}.${stamp}@trust.test`, publicKey: k.publicKeyHex, authProvider: "key", forceRole: role, forceStatus: "approved" })
    return { u, k }
  }
  const inv = await mk("investigator")
  const judge = await mk("judiciary")

  const results: Stat[] = []
  const login = async (who: { u: any; k: any }) => {
    const ch = await call("POST", "/api/auth/challenge", { json: { did: who.u.did } })
    const d = JSON.parse(ch.buf.toString()).data
    const v = await call("POST", "/api/auth/verify", { json: { did: d.did, nonce: d.nonce, signatureHex: signWithPrivateKeyPem(who.k.privateKeyPem, d.payload) } })
    return { ms: ch.ms + v.ms, token: JSON.parse(v.buf.toString()).data.token }
  }

  // 1. Login (challenge + signature verify + JWT)
  const loginMs: number[] = []
  let invToken = "", judgeToken = ""
  for (let i = 0; i < ITER; i++) { const r = await login(inv); loginMs.push(r.ms); invToken = r.token }
  judgeToken = (await login(judge)).token
  results.push(stats("Login (challenge + verify)", loginMs))

  // 2. Upload (hash + sign check + AES-GCM + storage + ledger commit + DB)
  const uploadMs: number[] = []
  const ids: string[] = []
  for (let i = 0; i < ITER; i++) {
    const file = crypto.randomBytes(FILE_KB * 1024)
    const hash = crypto.createHash("sha256").update(file).digest("hex")
    const form = new FormData()
    form.append("caseId", "CASE-BENCH")
    form.append("signature", signWithPrivateKeyPem(inv.k.privateKeyPem, signingPayloads.upload("CASE-BENCH", hash)))
    form.append("file", new Blob([file]), `bench-${i}.bin`)
    const r = await call("POST", "/api/evidence/upload", { token: invToken, form })
    uploadMs.push(r.ms)
    ids.push(JSON.parse(r.buf.toString()).data.id)
  }
  results.push(stats(`Upload ${FILE_KB} KB (end to end)`, uploadMs))

  // 3. Audited view (ledger write + decrypt + stream)
  const viewMs: number[] = []
  for (const id of ids) viewMs.push((await call("GET", `/api/evidence/${id}/view`, { token: invToken })).ms)
  results.push(stats("View (ledger-first, decrypt)", viewMs))

  // 4. Status change (signed, ledger-first)
  const statusMs: number[] = []
  for (const id of ids) {
    statusMs.push((await call("PATCH", `/api/evidence/${id}/status`, {
      token: judgeToken, json: { status: "verified", signature: signWithPrivateKeyPem(judge.k.privateKeyPem, signingPayloads.status(id, "verified")) }
    })).ms)
  }
  results.push(stats("Status change (judicial verify)", statusMs))

  // 5. Full custody verification
  const verifyMs: number[] = []
  for (const id of ids.slice(0, Math.min(ids.length, 20))) verifyMs.push((await call("GET", `/api/evidence/${id}/verify`, { token: judgeToken })).ms)
  results.push(stats("Custody verification", verifyMs))

  // 6. List evidence
  const listMs: number[] = []
  for (let i = 0; i < ITER; i++) listMs.push((await call("GET", "/api/evidence", { token: invToken })).ms)
  results.push(stats("List evidence", listMs))

  // 7. Raw ledger commit latency (no HTTP, no DB)
  const ledgerMs: number[] = []
  for (let i = 0; i < ITER; i++) {
    const t = performance.now()
    await hyperledgerService.recordAudit({ logId: `LOG-B${stamp}${i}`, targetId: ids[0], caseId: "CASE-BENCH", action: "bench", performedByDid: inv.u.did, mspId: "PoliceOrgMSP" })
    ledgerMs.push(performance.now() - t)
  }
  results.push(stats("Ledger commit (RecordAuditAccess)", ledgerMs))

  // 8. Throughput under concurrency (list endpoint)
  const total = ITER * CONC
  let done = 0
  const t0 = performance.now()
  const concMs: number[] = []
  await Promise.all(Array.from({ length: CONC }, async () => {
    while (done < total) { done++; concMs.push((await call("GET", "/api/evidence", { token: invToken })).ms) }
  }))
  const seconds = (performance.now() - t0) / 1000
  results.push(stats(`List under ${CONC} concurrent clients`, concMs))
  const throughput = total / seconds

  server.close()
  await hyperledgerService.close()

  const ledgerInfo = await hyperledgerService.info()
  const env = { node: process.version, cpu: os.cpus()[0]?.model, cores: os.cpus().length, database: dbMode, ledger: ledgerInfo.mode, iterations: ITER, concurrency: CONC, fileKB: FILE_KB }
  const fmt = (n: number) => n.toFixed(1)
  const lines = [
    `| Operation | n | mean ms | p50 ms | p95 ms | max ms |`,
    `| --- | --- | --- | --- | --- | --- |`,
    ...results.map(r => `| ${r.name} | ${r.n} | ${fmt(r.mean)} | ${fmt(r.p50)} | ${fmt(r.p95)} | ${fmt(r.max)} |`)
  ]
  const md = [`# TRUST benchmark (${new Date().toISOString()})`, "", "```", JSON.stringify(env, null, 2), "```", "", ...lines, "", `Throughput (list, ${CONC} concurrent): ${throughput.toFixed(0)} req/s`].join("\n")
  console.log(md)

  const outDir = path.join(__dirname, "..", "bench-results")
  fs.mkdirSync(outDir, { recursive: true })
  const name = new Date().toISOString().replace(/[:.]/g, "-")
  fs.writeFileSync(path.join(outDir, `${name}.json`), JSON.stringify({ env, results, throughputRps: throughput }, null, 2))
  fs.writeFileSync(path.join(outDir, `${name}.md`), md)
  process.exit(0)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
