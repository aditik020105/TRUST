import request from "supertest"
import express from "express"
import crypto from "crypto"
import fs from "fs"
import os from "os"
import path from "path"
import { app } from "../index"
import { createActor, signingPayloads, TestActor } from "./support/helpers"
import { hyperledgerService } from "../services/hyperledger.service"
import { verifySealedReport, canonicalJson } from "../services/report.service"
import { deliverOutbox, signWebhookBody } from "../services/audit-row.service"
import { createBackup, restoreBackup } from "../services/backup.service"
import { resetLocalDb, supabase } from "../lib/supabase"
import { resetDdosStore, stopCleanupTimer } from "../middleware/ddos.middleware"

const sha = (b: Buffer | string) => crypto.createHash("sha256").update(b).digest("hex")
let investigator: TestActor, judge: TestActor, admin: TestActor, analyst: TestActor

beforeAll(async () => {
  investigator = await createActor("investigator")
  judge = await createActor("judiciary")
  admin = await createActor("admin")
  analyst = await createActor("analyst")
})
beforeEach(() => resetDdosStore())
afterAll(() => stopCleanupTimer())

async function upload(caseId: string, content: string) {
  const buf = Buffer.from(content)
  const res = await request(app).post("/api/evidence/upload").set("Authorization", investigator.auth)
    .field("caseId", caseId).field("signature", investigator.sign(signingPayloads.upload(caseId, sha(buf)))).attach("file", buf, "item.txt")
  expect(res.status).toBe(201)
  return res.body.data.id as string
}

describe("Courtroom export", () => {
  it("JSON bundle is sealed: its hash is on the ledger and signed by the gateway", async () => {
    const id = await upload("CASE-COURT", "knife photo")
    await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", judge.auth)
      .send({ status: "verified", signature: judge.sign(signingPayloads.status(id, "verified")) })
    const res = await request(app).get(`/api/evidence/${id}/report?format=json`).set("Authorization", judge.auth)
    expect(res.status).toBe(200)
    const { report, seal } = res.body
    expect(report.verdict.verified).toBe(true)
    expect(report.custodyTimeline.map((t: any) => t.action)).toEqual(["uploaded", "status_verified"])
    expect(report.uploaderDidDocument.id).toBe(investigator.user.did)
    expect(sha(canonicalJson(report))).toBe(seal.reportHash)
    expect(verifySealedReport(report, seal.reportHash, seal.gatewaySignature)).toBe(true)

    const onLedger = (await hyperledgerService.listAudit()).find(a => a.txId === seal.exportTx)
    expect(onLedger?.action).toBe("report_exported")
    expect(JSON.parse(onLedger!.details).reportHash).toBe(seal.reportHash)

    // any edit to the report breaks the seal
    const edited = { ...report, verdict: { verified: true, failedChecks: [] }, evidence: { ...report.evidence, status: "flagged" } }
    expect(verifySealedReport(edited, seal.reportHash, seal.gatewaySignature)).toBe(false)

    const key = await request(app).get("/api/report-key")
    expect(key.body.data.publicKeyPem).toContain("BEGIN PUBLIC KEY")
  })

  it("PDF rendering", async () => {
    const id = await upload("CASE-COURT", "pdf me")
    const res = await request(app).get(`/api/evidence/${id}/report`).set("Authorization", judge.auth).buffer(true).parse((r, cb) => {
      const chunks: Buffer[] = []
      r.on("data", (c: Buffer) => chunks.push(c))
      r.on("end", () => cb(null, Buffer.concat(chunks)))
    })
    expect(res.status).toBe(200)
    expect(res.headers["content-type"]).toBe("application/pdf")
    expect((res.body as Buffer).subarray(0, 5).toString()).toBe("%PDF-")
    expect(res.headers["x-report-sha256"]).toMatch(/^[0-9a-f]{64}$/)
  })
})

describe("Legacy logbook import", () => {
  const csv = [
    "date,case_id,item,action,officer,notes",
    '2024-02-01,CASE-OLD-7,"Knife, kitchen",seized,Insp. Rao,"Bagged at scene"',
    "2024-02-03,CASE-OLD-7,\"Knife, kitchen\",transferred to lab,Insp. Rao,",
    ""
  ].join("\n")

  it("dry run validates without writing; bad rows are reported with line numbers", async () => {
    const bad = await request(app).post("/api/admin/legacy-import").set("Authorization", admin.auth)
      .attach("file", Buffer.from("date,case_id,item,action,officer\nnot-a-date,CASE-1,x,y,z\n"), "bad.csv")
    expect(bad.status).toBe(400)
    expect(bad.body.data.errors[0]).toMatch(/line 2: invalid date/)
    const dry = await request(app).post("/api/admin/legacy-import").set("Authorization", admin.auth)
      .field("dryRun", "true").attach("file", Buffer.from(csv), "logbook.csv")
    expect(dry.status).toBe(200)
    expect(dry.body.data.imported).toBe(0)
  })

  it("imports rows as attested ledger events plus a batch event with the file hash", async () => {
    const res = await request(app).post("/api/admin/legacy-import").set("Authorization", admin.auth).attach("file", Buffer.from(csv), "logbook.csv")
    expect(res.status).toBe(200)
    expect(res.body.data.imported).toBe(2)
    expect(res.body.data.fileSha256).toBe(sha(csv))
    const log = await request(app).get("/api/audit-log?caseId=CASE-OLD-7").set("Authorization", admin.auth)
    const actions = log.body.data.map((r: any) => r.action).sort()
    expect(actions).toEqual(["legacy_seized", "legacy_transferred_to_lab"])
    const d = JSON.parse(log.body.data[0].details)
    expect(d.attestation).toMatch(/not signed by the original officer/)
    expect(d.item).toBe("Knife, kitchen")
    expect((await request(app).post("/api/admin/legacy-import").set("Authorization", judge.auth).attach("file", Buffer.from(csv), "x.csv")).status).toBe(403)
  })
})

describe("Case-management connector", () => {
  it("pushes every custody event with an HMAC signature, retrying after a failure", async () => {
    const received: Array<{ body: string; sig: string; id: string }> = []
    let fail = true
    const receiver = express().post("/hook", express.text({ type: "*/*" }), (req, res) => {
      if (fail) return res.status(503).end()
      received.push({ body: req.body, sig: String(req.headers["x-trust-signature"]), id: String(req.headers["x-trust-event-id"]) })
      res.status(204).end()
    })
    const server = receiver.listen(0)
    process.env.CASE_MGMT_WEBHOOK_URL = `http://127.0.0.1:${(server.address() as any).port}/hook`
    process.env.CASE_MGMT_WEBHOOK_SECRET = "s3cret"
    try {
      const id = await upload("CASE-HOOK", "hook me")
      const first = await deliverOutbox()
      expect(first.failed).toBeGreaterThanOrEqual(1)
      fail = false
      await supabase.from("webhook_outbox").update({ next_attempt_at: new Date(0).toISOString() }).is("delivered_at", null)
      const second = await deliverOutbox()
      expect(second.delivered).toBeGreaterThanOrEqual(2) // case_opened + uploaded
      const upl = received.map(r => ({ ...r, json: JSON.parse(r.body) })).find(r => r.json.event.action === "uploaded" && r.json.event.evidenceId === id)
      expect(upl).toBeDefined()
      expect(upl!.sig).toBe(signWebhookBody(upl!.body, "s3cret"))
      expect(upl!.json.event.txHash).toMatch(/^[0-9a-f]{64}$/)
      expect((await deliverOutbox()).delivered).toBe(0) // nothing delivered twice
    } finally {
      delete process.env.CASE_MGMT_WEBHOOK_URL
      server.close()
    }
  })

  it("case custody export for external systems flags each event's ledger match", async () => {
    await upload("CASE-EXPORT", "export me")
    const res = await request(app).get("/api/cases/CASE-EXPORT/custody").set("Authorization", analyst.auth)
    expect(res.status).toBe(200)
    expect(res.body.data.evidence).toHaveLength(1)
    expect(res.body.data.events.every((e: any) => e.ledgerMatch)).toBe(true)
  })
})

describe("Backup, restore and failover", () => {
  it("restores into an empty database; reconciliation confirms it against the ledger", async () => {
    const id = await upload("CASE-BACKUP", "back me up")
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trust-backup-"))
    await createBackup(dir)

    // simulate losing the database and object storage (the ledger survives on its peers)
    resetLocalDb()
    fs.rmSync(path.join(process.env.STORAGE_DIR!, "evidence-files"), { recursive: true, force: true })
    expect((await request(app).get(`/api/evidence/${id}`).set("Authorization", judge.auth)).status).toBe(401) // users gone too

    const r = await restoreBackup(dir)
    expect(r.blobs).toBeGreaterThan(0)
    // On a shared Fabric network the ledger also holds other test files' events; only this database's rows matter.
    const relevant = process.env.LEDGER_MODE === "fabric"
      ? r.reconciliation.issues.filter(i => !["audit_missing_in_db", "evidence_missing_in_db"].includes(i.kind))
      : r.reconciliation.issues
    expect(relevant).toEqual([])
    const view = await request(app).get(`/api/evidence/${id}/view`).set("Authorization", judge.auth)
    expect(view.status).toBe(200)
    expect(view.text).toBe("back me up")
  })

  it("an out-of-date backup is caught: changes made after it show up as ledger mismatches", async () => {
    const id = await upload("CASE-STALE", "stale")
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trust-backup-"))
    await createBackup(dir)
    await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", judge.auth)
      .send({ status: "verified", signature: judge.sign(signingPayloads.status(id, "verified")) })
    resetLocalDb()
    const r = await restoreBackup(dir)
    const kinds = r.reconciliation.issues.map(i => `${i.kind}:${i.id}`)
    expect(kinds).toContain(`evidence_mismatch:${id}`)
    expect(r.reconciliation.issues.some(i => i.kind === "audit_missing_in_db")).toBe(true)
  })

  it("refuses a tampered backup and a non-empty target", async () => {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trust-backup-"))
    await createBackup(dir)
    await expect(restoreBackup(dir)).rejects.toThrow(/not empty/)
    const f = path.join(dir, "evidence.json")
    fs.writeFileSync(f, fs.readFileSync(f, "utf-8").replace(/"pending"/, '"verified"'))
    resetLocalDb()
    await expect(restoreBackup(dir)).rejects.toThrow(/manifest hash/)
  })
})
