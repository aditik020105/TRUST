import request from "supertest"
import crypto from "crypto"
import { app } from "../index"
import { createActor, signingPayloads, TestActor } from "./support/helpers"
import { supabase } from "../lib/supabase"
import { opaService } from "../services/opa.service"
import { resetDdosStore, stopCleanupTimer } from "../middleware/ddos.middleware"

let admin: TestActor, investigator: TestActor, analyst: TestActor, judge: TestActor, auditor: TestActor
let pending: TestActor, revoked: TestActor

beforeAll(async () => {
  admin = await createActor("admin")
  investigator = await createActor("investigator")
  analyst = await createActor("analyst")
  judge = await createActor("judiciary")
  auditor = await createActor("auditor")
  pending = await createActor("investigator", "pending")
  revoked = await createActor("analyst", "revoked")
})
beforeEach(() => resetDdosStore())
afterAll(() => stopCleanupTimer())

const sha = (s: string) => crypto.createHash("sha256").update(s).digest("hex")

describe("OPA role matrix (paper Table III)", () => {
  const cases: Array<[string, string, Record<string, any>, Record<string, boolean>]> = [
    ["upload_evidence", "upload", {}, { admin: true, investigator: true, analyst: true, judiciary: false, auditor: false }],
    ["view_evidence", "view", {}, { admin: true, investigator: true, analyst: true, judiciary: true, auditor: true }],
    ["update_evidence_status", "flag", { status: "flagged" }, { admin: true, investigator: false, analyst: true, judiciary: true, auditor: false }],
    ["update_evidence_status", "verify", { status: "verified" }, { admin: true, investigator: false, analyst: false, judiciary: true, auditor: false }],
    ["approve_user", "admin", {}, { admin: true, investigator: false, analyst: false, judiciary: false, auditor: false }],
    ["audit_ledger", "oversight", {}, { admin: true, investigator: false, analyst: false, judiciary: false, auditor: true }]
  ]
  for (const [action, label, parameters, expected] of cases) {
    for (const [role, allow] of Object.entries(expected)) {
      it(`${role} ${allow ? "may" : "may not"} ${label}`, () => {
        const d = opaService.evaluateEmbeddedRego({
          method: "T", path: "/", resource: "/", action, parameters,
          user: { did: `did:trust:${role}:x`, role, mspId: "M", status: "approved" }
        })
        expect(d.allow).toBe(allow)
      })
    }
  }

  it("denies every action to pending and revoked accounts, whatever their role", async () => {
    for (const actor of [pending, revoked]) {
      const ev = await request(app).get("/api/evidence").set("Authorization", actor.auth)
      expect(ev.status).toBe(403)
      const audit = await request(app).get("/api/audit-log").set("Authorization", actor.auth)
      expect(audit.status).toBe(403)
    }
  })

  it("returns the deciding rule in X-OPA headers", async () => {
    const res = await request(app).get("/api/admin/users").set("Authorization", judge.auth)
    expect(res.status).toBe(403)
    expect(res.headers["x-opa-decision"]).toBe("DENY")
    expect(res.headers["x-opa-rule"]).toBe("allow_admin_authorization")
  })
})

describe("Admin endpoints are protected", () => {
  it("only admins list users; auditors see policy and ledger status but not users or firewall", async () => {
    expect((await request(app).get("/api/admin/users").set("Authorization", admin.auth)).status).toBe(200)
    expect((await request(app).get("/api/admin/users").set("Authorization", investigator.auth)).status).toBe(403)
    expect((await request(app).get("/api/admin/users")).status).toBe(401)
    expect((await request(app).get("/api/admin/opa").set("Authorization", auditor.auth)).status).toBe(200)
    expect((await request(app).get("/api/admin/ledger").set("Authorization", auditor.auth)).status).toBe(200)
    expect((await request(app).get("/api/admin/firewall").set("Authorization", auditor.auth)).status).toBe(403)
    expect((await request(app).get("/api/admin/firewall").set("Authorization", admin.auth)).status).toBe(200)
    expect((await request(app).post("/api/admin/opa/evaluate").send({ role: "admin" })).status).toBe(401)
  })
})

describe("Approve / revoke lifecycle", () => {
  it("pending user is blocked until approved, then blocked again after revocation; each step is on the ledger", async () => {
    const cadet = await createActor("investigator", "pending")
    expect((await request(app).get("/api/evidence").set("Authorization", cadet.auth)).status).toBe(403)

    const approve = await request(app).patch(`/api/admin/users/${cadet.user.uid}/authorize`).set("Authorization", admin.auth).send({ status: "approved" })
    expect(approve.status).toBe(200)
    expect(approve.body.txHash).toMatch(/^[0-9a-f]{64}$/)
    expect((await request(app).get("/api/evidence").set("Authorization", cadet.auth)).status).toBe(200)

    const revoke = await request(app).patch(`/api/admin/users/${cadet.user.uid}/authorize`).set("Authorization", admin.auth).send({ status: "revoked" })
    expect(revoke.status).toBe(200)
    // same session token, revoked immediately
    expect((await request(app).get("/api/evidence").set("Authorization", cadet.auth)).status).toBe(403)

    const log = await request(app).get(`/api/audit-log?evidenceId=${encodeURIComponent(cadet.user.did)}`).set("Authorization", admin.auth)
    expect(log.body.data.map((r: any) => r.action).sort()).toEqual(["did_registered_pending", "user_approved", "user_revoked"])
  })

  it("judiciary can no longer approve users", async () => {
    const cadet = await createActor("investigator", "pending")
    const res = await request(app).patch(`/api/admin/users/${cadet.user.uid}/authorize`).set("Authorization", judge.auth).send({ status: "approved" })
    expect(res.status).toBe(403)
  })

  it("admins cannot revoke themselves", async () => {
    const res = await request(app).patch(`/api/admin/users/${admin.user.uid}/authorize`).set("Authorization", admin.auth).send({ status: "revoked" })
    expect(res.status).toBe(400)
  })
})

describe("DID resolution", () => {
  it("resolves a registered DID and verifies a signature made in the client", async () => {
    const doc = await request(app).get(`/api/did/${encodeURIComponent(analyst.user.did)}`)
    expect(doc.status).toBe(200)
    expect(doc.body.data.verificationMethod[0].type).toBe("Ed25519VerificationKey2020")
    const payload = "TRUST-CUSTODY-CHALLENGE-1"
    const ok = await request(app).post("/api/did/verify").send({ did: analyst.user.did, payload, signatureHex: analyst.sign(payload) })
    expect(ok.body.data.verified).toBe(true)
    const bad = await request(app).post("/api/did/verify").send({ did: analyst.user.did, payload, signatureHex: judge.sign(payload) })
    expect(bad.body.data.verified).toBe(false)
  })
})

describe("Reconciliation", () => {
  it("reports DB rows with no ledger transaction and passes when stores agree", async () => {
    const buf = Buffer.from("reconcile")
    const sig = investigator.sign(signingPayloads.upload("CASE-R", sha("reconcile")))
    const up = await request(app).post("/api/evidence/upload").set("Authorization", investigator.auth)
      .field("caseId", "CASE-R").field("signature", sig).attach("file", buf, "r.txt")
    expect(up.status).toBe(201)

    const clean = await request(app).post("/api/admin/reconcile").set("Authorization", auditor.auth)
    // A shared Fabric network also holds events from other test files' databases, so only the
    // local ledger (fresh per file) can be expected to be completely clean.
    const relevant = (issues: any[]) => process.env.LEDGER_MODE === "fabric" ? issues.filter(i => i.kind !== "audit_missing_in_db" && i.kind !== "evidence_missing_in_db") : issues
    expect(relevant(clean.body.data.issues)).toEqual([])

    await supabase.from("audit_log").insert({
      id: "LOG-GHOST01", evidence_id: up.body.data.id, case_id: "CASE-R", action: "viewed",
      performed_by: judge.user.did, timestamp: new Date().toISOString(), tx_hash: "0".repeat(64)
    })
    const dirty = await request(app).post("/api/admin/reconcile").set("Authorization", admin.auth)
    expect(dirty.body.data.ok).toBe(false)
    expect(relevant(dirty.body.data.issues)).toEqual([expect.objectContaining({ kind: "audit_missing_on_ledger", id: "LOG-GHOST01" })])
  })
})
