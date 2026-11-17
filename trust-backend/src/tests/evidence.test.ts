import request from "supertest"
import crypto from "crypto"
import fs from "fs"
import path from "path"
import { app } from "../index"
import { createActor, signingPayloads, TestActor } from "./support/helpers"
import { hyperledgerService, LedgerUnavailableError } from "../services/hyperledger.service"
import { supabase } from "../lib/supabase"
import { resetDdosStore, stopCleanupTimer } from "../middleware/ddos.middleware"

const sha = (b: Buffer) => crypto.createHash("sha256").update(b).digest("hex")
const storageFile = (rel: string) => path.join(process.env.STORAGE_DIR!, "evidence-files", rel)

let investigator: TestActor
let analyst: TestActor
let judge: TestActor
let auditor: TestActor

beforeAll(async () => {
  investigator = await createActor("investigator")
  analyst = await createActor("analyst")
  judge = await createActor("judiciary")
  auditor = await createActor("auditor")
})
beforeEach(() => resetDdosStore())
afterEach(() => jest.restoreAllMocks())
afterAll(() => stopCleanupTimer())

async function upload(actor: TestActor, content: string, caseId = "CASE-2026-001", signature?: string) {
  const buf = Buffer.from(content)
  const sig = signature ?? actor.sign(signingPayloads.upload(caseId, sha(buf)))
  return request(app)
    .post("/api/evidence/upload")
    .set("Authorization", actor.auth)
    .field("caseId", caseId)
    .field("signature", sig)
    .attach("file", buf, { filename: "scene.txt", contentType: "text/plain" })
}

describe("Upload", () => {
  it("anchors the hash, encrypts the file at rest and records the upload", async () => {
    const res = await upload(investigator, "crime scene notes")
    expect(res.status).toBe(201)
    const ev = res.body.data
    expect(ev.hash).toBe(sha(Buffer.from("crime scene notes")))
    expect(ev.uploadedBy).toBe(investigator.user.did)
    expect(ev.encryption).toBe("aes-256-gcm")
    expect(res.body.txHash).toMatch(/^[0-9a-f]{64}$/)
    expect(typeof res.body.blockNumber).toBe("number")

    const onDisk = fs.readFileSync(storageFile(`cases/CASE-2026-001/${ev.id}.enc`))
    expect(onDisk.subarray(0, 9).toString()).toBe("TRUSTENC1")
    expect(onDisk.includes(Buffer.from("crime scene notes"))).toBe(false)

    const onLedger = await hyperledgerService.readEvidence(ev.id)
    expect(onLedger?.fileHash).toBe(ev.hash)
    expect(onLedger?.createdTxId).toBe(res.body.txHash)

    const log = await request(app).get(`/api/audit-log?evidenceId=${ev.id}`).set("Authorization", investigator.auth)
    expect(log.body.data.map((r: any) => r.action)).toEqual(["uploaded"])
    expect(log.body.data[0].txHash).toBe(res.body.txHash)
  })

  it("ignores any uploadedBy in the body and uses the caller's DID", async () => {
    const buf = Buffer.from("spoof attempt")
    const res = await request(app)
      .post("/api/evidence/upload")
      .set("Authorization", investigator.auth)
      .field("caseId", "CASE-X")
      .field("uploadedBy", judge.user.did)
      .field("signature", investigator.sign(signingPayloads.upload("CASE-X", sha(buf))))
      .attach("file", buf, "a.txt")
    expect(res.status).toBe(201)
    expect(res.body.data.uploadedBy).toBe(investigator.user.did)
  })

  it("rejects missing or wrong signatures, missing caseId and missing file", async () => {
    expect((await upload(investigator, "x", "CASE-1", "")).status).toBe(400)
    const wrongKey = await upload(investigator, "x", "CASE-1", analyst.sign(signingPayloads.upload("CASE-1", sha(Buffer.from("x")))))
    expect(wrongKey.status).toBe(400)
    expect(wrongKey.body.code).toBe("SIGNATURE_INVALID")
    const wrongHash = await upload(investigator, "x", "CASE-1", investigator.sign(signingPayloads.upload("CASE-1", sha(Buffer.from("y")))))
    expect(wrongHash.status).toBe(400)
    const noCase = await request(app).post("/api/evidence/upload").set("Authorization", investigator.auth).attach("file", Buffer.from("x"), "a.txt")
    expect(noCase.status).toBe(400)
    const noFile = await request(app).post("/api/evidence/upload").set("Authorization", investigator.auth).field("caseId", "C").field("signature", "ab")
    expect(noFile.status).toBe(400)
  })

  it("fails closed and removes the stored blob when the ledger is unavailable", async () => {
    jest.spyOn(hyperledgerService, "createEvidence").mockRejectedValueOnce(new LedgerUnavailableError("peer down"))
    const before = (await supabase.from("evidence").select("*")).data.length
    const res = await upload(investigator, "ledger down", "CASE-DOWN")
    expect(res.status).toBe(502)
    expect(res.body.code).toBe("LEDGER_UNAVAILABLE")
    expect((await supabase.from("evidence").select("*")).data.length).toBe(before)
    const dir = path.join(process.env.STORAGE_DIR!, "evidence-files", "cases", "CASE-DOWN")
    expect(fs.existsSync(dir) ? fs.readdirSync(dir) : []).toHaveLength(0)
  })

  it("judiciary cannot upload (separation of duties)", async () => {
    const res = await upload(judge, "court upload")
    expect(res.status).toBe(403)
    expect(res.headers["x-opa-decision"]).toBe("DENY")
  })
})

describe("Audited view and download", () => {
  it("records the view on the ledger before returning the decrypted file", async () => {
    const up = await upload(investigator, "photo bytes")
    const id = up.body.data.id
    const res = await request(app).get(`/api/evidence/${id}/view`).set("Authorization", analyst.auth)
    expect(res.status).toBe(200)
    expect(res.text).toBe("photo bytes")
    expect(res.headers["content-disposition"]).toMatch(/^inline/)
    expect(res.headers["cache-control"]).toBe("no-store")
    expect(res.headers["x-content-type-options"]).toBe("nosniff")
    const ledgerTx = res.headers["x-ledger-tx"]
    const audits = (await hyperledgerService.listAudit()).filter(a => a.targetId === id && a.action === "viewed")
    expect(audits).toHaveLength(1)
    expect(audits[0].txId).toBe(ledgerTx)
    expect(audits[0].performedByDid).toBe(analyst.user.did)
  })

  it("download is audited too", async () => {
    const up = await upload(investigator, "download me")
    const res = await request(app).get(`/api/evidence/${up.body.data.id}/download`).set("Authorization", auditor.auth)
    expect(res.status).toBe(200)
    expect(res.headers["content-disposition"]).toMatch(/^attachment/)
    const log = await request(app).get(`/api/audit-log?evidenceId=${up.body.data.id}&action=downloaded`).set("Authorization", auditor.auth)
    expect(log.body.data).toHaveLength(1)
    expect(log.body.data[0].performedBy).toBe(auditor.user.did)
  })

  it("does not release the file if the ledger write fails", async () => {
    const up = await upload(investigator, "secret")
    jest.spyOn(hyperledgerService, "recordAudit").mockRejectedValueOnce(new LedgerUnavailableError("peer down"))
    const res = await request(app).get(`/api/evidence/${up.body.data.id}/view`).set("Authorization", analyst.auth)
    expect(res.status).toBe(502)
    expect(res.text).not.toContain("secret")
  })

  it("refuses to serve a stored file that was altered", async () => {
    const up = await upload(investigator, "original")
    const file = storageFile(`cases/CASE-2026-001/${up.body.data.id}.enc`)
    const blob = fs.readFileSync(file)
    blob[blob.length - 1] ^= 0xff
    fs.writeFileSync(file, blob)
    const res = await request(app).get(`/api/evidence/${up.body.data.id}/view`).set("Authorization", analyst.auth)
    expect(res.status).toBe(409)
    expect(res.body.code).toBe("INTEGRITY_FAILURE")
  })

  it("raw storage is not exposed over HTTP", async () => {
    const up = await upload(investigator, "hidden")
    const res = await request(app).get(`/storage/evidence-files/cases/CASE-2026-001/${up.body.data.id}.enc`)
    expect(res.status).toBe(404)
  })
})

describe("Status governance", () => {
  it("judge verifies with a signed request; ledger and DB agree", async () => {
    const up = await upload(investigator, "to verify")
    const id = up.body.data.id
    const res = await request(app)
      .patch(`/api/evidence/${id}/status`)
      .set("Authorization", judge.auth)
      .send({ status: "verified", signature: judge.sign(signingPayloads.status(id, "verified")) })
    expect(res.status).toBe(200)
    expect(res.body.data.status).toBe("verified")
    expect((await hyperledgerService.readEvidence(id))?.status).toBe("verified")
  })

  it("analyst may flag but not verify; investigator may do neither", async () => {
    const up = await upload(investigator, "to flag")
    const id = up.body.data.id
    const flag = await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", analyst.auth)
      .send({ status: "flagged", signature: analyst.sign(signingPayloads.status(id, "flagged")) })
    expect(flag.status).toBe(200)
    const verify = await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", analyst.auth)
      .send({ status: "verified", signature: analyst.sign(signingPayloads.status(id, "verified")) })
    expect(verify.status).toBe(403)
    const inv = await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", investigator.auth)
      .send({ status: "flagged", signature: investigator.sign(signingPayloads.status(id, "flagged")) })
    expect(inv.status).toBe(403)
  })

  it("rejects unsigned, mis-signed and invalid status changes", async () => {
    const up = await upload(investigator, "sig check")
    const id = up.body.data.id
    expect((await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", judge.auth).send({ status: "verified" })).status).toBe(400)
    const wrong = await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", judge.auth)
      .send({ status: "verified", signature: judge.sign(signingPayloads.status(id, "flagged")) })
    expect(wrong.status).toBe(400)
    expect((await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", judge.auth).send({ status: "gone", signature: "ab" })).status).toBe(400)
    expect((await request(app).patch(`/api/evidence/EV-NOPE/status`).set("Authorization", judge.auth)
      .send({ status: "verified", signature: judge.sign(signingPayloads.status("EV-NOPE", "verified")) })).status).toBe(404)
  })

  it("does not change the database when the ledger rejects the update", async () => {
    const up = await upload(investigator, "ledger first")
    const id = up.body.data.id
    jest.spyOn(hyperledgerService, "updateEvidenceStatus").mockRejectedValueOnce(new LedgerUnavailableError("down"))
    const res = await request(app).patch(`/api/evidence/${id}/status`).set("Authorization", judge.auth)
      .send({ status: "verified", signature: judge.sign(signingPayloads.status(id, "verified")) })
    expect(res.status).toBe(502)
    const row = (await supabase.from("evidence").select("*").eq("id", id).single()).data
    expect(row.status).toBe("pending")
  })
})

describe("Custody verification", () => {
  it("passes every check for an untouched record and logs the check itself", async () => {
    const up = await upload(investigator, "verify me")
    const id = up.body.data.id
    await request(app).get(`/api/evidence/${id}/view`).set("Authorization", analyst.auth)
    const res = await request(app).get(`/api/evidence/${id}/verify`).set("Authorization", judge.auth)
    expect(res.status).toBe(200)
    const failed = res.body.data.checks.filter((c: any) => !c.ok)
    expect(failed).toEqual([])
    expect(res.body.data.verified).toBe(true)
    expect(res.body.data.timeline.map((t: any) => t.action)).toEqual(["uploaded", "viewed"])
    const log = await request(app).get(`/api/audit-log?evidenceId=${id}&action=integrity_checked`).set("Authorization", judge.auth)
    expect(log.body.data).toHaveLength(1)
  })

  it("detects a database hash edited after upload by comparing against the ledger", async () => {
    const up = await upload(investigator, "db tamper")
    const id = up.body.data.id
    await supabase.from("evidence").update({ hash: "0".repeat(64) }).eq("id", id)
    const res = await request(app).get(`/api/evidence/${id}/verify`).set("Authorization", judge.auth)
    expect(res.body.data.verified).toBe(false)
    expect(res.body.data.checks.find((c: any) => c.name === "Database row matches ledger").ok).toBe(false)
    // the file itself still matches the ledger, which is what proves the DB was edited
    expect(res.body.data.checks.find((c: any) => c.name === "File SHA-256 matches ledger").ok).toBe(true)
  })

  it("detects a forged audit row inserted directly into the database", async () => {
    const up = await upload(investigator, "audit tamper")
    const id = up.body.data.id
    await supabase.from("audit_log").insert({
      id: "LOG-FORGED1", evidence_id: id, case_id: "CASE-2026-001", action: "status_verified",
      performed_by: judge.user.did, timestamp: new Date().toISOString(), tx_hash: "f".repeat(64)
    })
    const res = await request(app).get(`/api/evidence/${id}/verify`).set("Authorization", auditor.auth)
    expect(res.body.data.verified).toBe(false)
    const forged = res.body.data.timeline.find((t: any) => t.id === "LOG-FORGED1")
    expect(forged.ledgerMatch).toBe(false)
  })
})

describe("Audit log filters", () => {
  it("filters by case, performer and action", async () => {
    await upload(investigator, "f1", "CASE-FILTER")
    await upload(analyst, "f2", "CASE-FILTER")
    const byCase = await request(app).get("/api/audit-log?caseId=CASE-FILTER").set("Authorization", auditor.auth)
    expect(byCase.body.data.map((r: any) => r.action).sort()).toEqual(["case_opened", "uploaded", "uploaded"])
    const byPerformer = await request(app).get(`/api/audit-log?caseId=CASE-FILTER&performedBy=${encodeURIComponent(analyst.user.did)}`).set("Authorization", auditor.auth)
    expect(byPerformer.body.data.map((r: any) => r.action)).toEqual(["uploaded"])
    const byAction = await request(app).get("/api/audit-log?caseId=CASE-FILTER&action=viewed").set("Authorization", auditor.auth)
    expect(byAction.body.data).toHaveLength(0)
  })
})

describe("Private case notes (private data collection)", () => {
  it("keeps notes out of the database and blocks, readable only by member organisations and allowed roles", async () => {
    const buf = Buffer.from("witness statement scan")
    const res = await request(app).post("/api/evidence/upload").set("Authorization", investigator.auth)
      .field("caseId", "CASE-PDC").field("notes", "Witness: Ravi Kumar, 12 MG Road")
      .field("signature", investigator.sign(signingPayloads.upload("CASE-PDC", sha(buf))))
      .attach("file", buf, "statement.pdf")
    expect(res.status).toBe(201)
    const id = res.body.data.id

    const row = (await supabase.from("evidence").select("*").eq("id", id).single()).data
    expect(JSON.stringify(row)).not.toContain("Ravi Kumar")
    const onLedger = await hyperledgerService.readEvidence(id)
    expect(onLedger?.privateDetailsHash).toMatch(/^[0-9a-f]{64}$/)
    if (process.env.LEDGER_MODE !== "fabric") {
      const ledgerFile = fs.readFileSync(path.join(process.env.DATA_DIR!, "ledger.json"), "utf-8")
      expect(ledgerFile).not.toContain("Ravi Kumar")
    }

    const inv = await request(app).get(`/api/evidence/${id}/private`).set("Authorization", investigator.auth)
    expect(inv.status).toBe(200)
    expect(inv.body.data.notes).toBe("Witness: Ravi Kumar, 12 MG Road")
    expect(inv.body.data.hashMatches).toBe(true)
    const judgeRead = await request(app).get(`/api/evidence/${id}/private`).set("Authorization", judge.auth)
    expect(judgeRead.status).toBe(200)
    // forensic analysts: denied by policy (and their organisation's peer does not hold the data)
    expect((await request(app).get(`/api/evidence/${id}/private`).set("Authorization", analyst.auth)).status).toBe(403)
    expect((await request(app).get(`/api/evidence/${id}/private`).set("Authorization", auditor.auth)).status).toBe(403)
  })
})
