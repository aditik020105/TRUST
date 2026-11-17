import request from "supertest"
import crypto from "crypto"
import { app } from "../index"
import { createActor, signingPayloads, TestActor } from "./support/helpers"
import { caseAccessService } from "../services/case-access.service"
import { supabase } from "../lib/supabase"
import { resetDdosStore, stopCleanupTimer } from "../middleware/ddos.middleware"

const sha = (b: Buffer) => crypto.createHash("sha256").update(b).digest("hex")
let owner: TestActor, otherInvestigator: TestActor, analyst: TestActor, judge: TestActor, auditor: TestActor, admin: TestActor

beforeAll(async () => {
  process.env.CASE_ACCESS_MODE = "restricted"
  owner = await createActor("investigator")
  otherInvestigator = await createActor("investigator")
  analyst = await createActor("analyst")
  judge = await createActor("judiciary")
  auditor = await createActor("auditor")
  admin = await createActor("admin")
})
afterAll(() => {
  process.env.CASE_ACCESS_MODE = "open"
  stopCleanupTimer()
})
beforeEach(() => resetDdosStore())

async function upload(actor: TestActor, caseId: string, content: string) {
  const buf = Buffer.from(content)
  return request(app).post("/api/evidence/upload").set("Authorization", actor.auth)
    .field("caseId", caseId).field("signature", actor.sign(signingPayloads.upload(caseId, sha(buf)))).attach("file", buf, "f.txt")
}

describe("Case-scoped access with time-bound delegation", () => {
  let evidenceId: string
  let grantId: string

  it("first upload opens the case; the uploader owns it and the opening is on the ledger", async () => {
    const res = await upload(owner, "CASE-SEC-1", "scene photo")
    expect(res.status).toBe(201)
    evidenceId = res.body.data.id
    const c = await caseAccessService.getCase("CASE-SEC-1")
    expect(c?.owner_did).toBe(owner.user.did)
    const log = await request(app).get("/api/audit-log?caseId=CASE-SEC-1&action=case_opened").set("Authorization", owner.auth)
    expect(log.body.data).toHaveLength(1)
  })

  it("other investigators and analysts cannot see or open the case; oversight roles can read it", async () => {
    const list = await request(app).get("/api/evidence").set("Authorization", analyst.auth)
    expect(list.body.data.map((e: any) => e.id)).not.toContain(evidenceId)
    expect((await request(app).get(`/api/evidence/${evidenceId}/view`).set("Authorization", analyst.auth)).status).toBe(403)
    expect((await request(app).get(`/api/evidence/${evidenceId}`).set("Authorization", otherInvestigator.auth)).status).toBe(403)
    expect((await upload(otherInvestigator, "CASE-SEC-1", "intruder")).status).toBe(403)
    expect((await request(app).get(`/api/evidence/${evidenceId}/view`).set("Authorization", judge.auth)).status).toBe(200)
    expect((await request(app).get(`/api/evidence/${evidenceId}`).set("Authorization", auditor.auth)).status).toBe(200)
    const audit = await request(app).get("/api/audit-log?caseId=CASE-SEC-1").set("Authorization", analyst.auth)
    expect(audit.body.data).toHaveLength(0)
  })

  it("owner delegates time-limited access; the grant is a ledger event", async () => {
    const res = await request(app).post("/api/cases/CASE-SEC-1/access").set("Authorization", owner.auth)
      .send({ granteeDid: analyst.user.did, permission: "contribute", expiresInHours: 2 })
    expect(res.status).toBe(201)
    grantId = res.body.data.id
    expect(res.body.data.state).toBe("active")
    expect(new Date(res.body.data.expiresAt).getTime() - Date.now()).toBeGreaterThan(1.9 * 3600 * 1000)
    expect((await request(app).get(`/api/evidence/${evidenceId}/view`).set("Authorization", analyst.auth)).status).toBe(200)
    expect((await upload(analyst, "CASE-SEC-1", "lab report")).status).toBe(201)
    const log = await request(app).get("/api/audit-log?caseId=CASE-SEC-1&action=access_granted").set("Authorization", analyst.auth)
    expect(log.body.data).toHaveLength(1)
    expect(log.body.data[0].txHash).toMatch(/^[0-9a-f]{64}$/)
  })

  it("only the owner or an admin can delegate, within limits", async () => {
    const byOther = await request(app).post("/api/cases/CASE-SEC-1/access").set("Authorization", otherInvestigator.auth)
      .send({ granteeDid: otherInvestigator.user.did, permission: "read", expiresInHours: 1 })
    expect(byOther.status).toBe(403)
    const tooLong = await request(app).post("/api/cases/CASE-SEC-1/access").set("Authorization", owner.auth)
      .send({ granteeDid: otherInvestigator.user.did, permission: "read", expiresInHours: 100000 })
    expect(tooLong.status).toBe(400)
    const judgeContribute = await request(app).post("/api/cases/CASE-SEC-1/access").set("Authorization", owner.auth)
      .send({ granteeDid: judge.user.did, permission: "contribute", expiresInHours: 1 })
    expect(judgeContribute.status).toBe(400)
    const byAdmin = await request(app).post("/api/cases/CASE-SEC-1/access").set("Authorization", admin.auth)
      .send({ granteeEmail: otherInvestigator.user.email, permission: "read", expiresInHours: 1 })
    expect(byAdmin.status).toBe(201)
  })

  it("revocation takes effect immediately and is recorded", async () => {
    const res = await request(app).post(`/api/cases/CASE-SEC-1/access/${grantId}/revoke`).set("Authorization", owner.auth)
    expect(res.status).toBe(200)
    expect(res.body.data.state).toBe("revoked")
    expect((await request(app).get(`/api/evidence/${evidenceId}/view`).set("Authorization", analyst.auth)).status).toBe(403)
    const again = await request(app).post(`/api/cases/CASE-SEC-1/access/${grantId}/revoke`).set("Authorization", owner.auth)
    expect(again.status).toBe(400)
  })

  it("expired delegations stop working and the expiry is written to the ledger once", async () => {
    const g = await request(app).post("/api/cases/CASE-SEC-1/access").set("Authorization", owner.auth)
      .send({ granteeDid: analyst.user.did, permission: "read", expiresInHours: 1 })
    expect((await request(app).get(`/api/evidence/${evidenceId}`).set("Authorization", analyst.auth)).status).toBe(200)
    await supabase.from("case_access").update({ expires_at: new Date(Date.now() - 1000).toISOString() }).eq("id", g.body.data.id)
    expect((await request(app).get(`/api/evidence/${evidenceId}`).set("Authorization", analyst.auth)).status).toBe(403)
    expect(await caseAccessService.recordExpiries()).toBeGreaterThanOrEqual(1)
    expect(await caseAccessService.recordExpiries()).toBe(0)
    const log = await request(app).get("/api/audit-log?caseId=CASE-SEC-1&action=access_expired").set("Authorization", owner.auth)
    expect(log.body.data.length).toBeGreaterThanOrEqual(1)
  })

  it("lists cases with the caller's access level and the delegations owners can see", async () => {
    const mine = await request(app).get("/api/cases").set("Authorization", owner.auth)
    const c = mine.body.data.find((x: any) => x.caseId === "CASE-SEC-1")
    expect(c.access).toBe("owner")
    expect(c.grants.map((g: any) => g.state).sort()).toEqual(["active", "expired", "revoked"])
    const theirs = await request(app).get("/api/cases").set("Authorization", analyst.auth)
    expect(theirs.body.data.find((x: any) => x.caseId === "CASE-SEC-1")).toBeUndefined()
  })
})
