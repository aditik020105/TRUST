import request from "supertest"
import crypto from "crypto"
import { app } from "../index"
import { createActor, signingPayloads, TestActor } from "./support/helpers"
import { generateEd25519KeyPair, signWithPrivateKeyPem } from "../services/did.service"
import { resetDdosStore, stopCleanupTimer } from "../middleware/ddos.middleware"

const sha = (b: Buffer) => crypto.createHash("sha256").update(b).digest("hex")
let admin1: TestActor, admin2: TestActor, admin3: TestActor, officer: TestActor, judge: TestActor

beforeAll(async () => {
  admin1 = await createActor("admin")
  admin2 = await createActor("admin")
  admin3 = await createActor("admin")
  officer = await createActor("investigator")
  judge = await createActor("judiciary")
})
beforeEach(() => resetDdosStore())
afterAll(() => stopCleanupTimer())

async function login(did: string, privateKeyPem: string) {
  const ch = await request(app).post("/api/auth/challenge").send({ did })
  if (ch.status !== 200) return ch
  return request(app).post("/api/auth/verify").send({ did, nonce: ch.body.data.nonce, signatureHex: signWithPrivateKeyPem(privateKeyPem, ch.body.data.payload) })
}

describe("Lost-key recovery needs two different administrators", () => {
  let oldEvidence: string
  let requestId: string
  let newDid: string
  const newKey = generateEd25519KeyPair()

  it("an upload signed with the old key exists", async () => {
    const buf = Buffer.from("signed before the key was lost")
    const res = await request(app).post("/api/evidence/upload").set("Authorization", officer.auth)
      .field("caseId", "CASE-REC").field("signature", officer.sign(signingPayloads.upload("CASE-REC", sha(buf)))).attach("file", buf, "a.txt")
    expect(res.status).toBe(201)
    oldEvidence = res.body.data.id
  })

  it("files a recovery request with a new browser-generated key; nothing changes yet", async () => {
    const res = await request(app).post("/api/recovery/request").send({ email: officer.user.email, newPublicKeyHex: newKey.publicKeyHex, reason: "laptop stolen" })
    expect(res.status).toBe(201)
    expect(res.body.data.requiredApprovals).toBe(2)
    requestId = res.body.data.id
    newDid = res.body.data.newDid
    expect((await login(newDid, newKey.privateKeyPem)).status).toBe(404) // new DID not active yet
    expect((await request(app).get("/api/evidence").set("Authorization", officer.auth)).status).toBe(200) // old session still valid
    const dup = await request(app).post("/api/recovery/request").send({ email: officer.user.email, newPublicKeyHex: generateEd25519KeyPair().publicKeyHex })
    expect(dup.status).toBe(409)
  })

  it("non-admins cannot approve; one admin is not enough; the same admin cannot approve twice", async () => {
    expect((await request(app).post(`/api/admin/recovery/${requestId}/approve`).set("Authorization", judge.auth)).status).toBe(403)
    const first = await request(app).post(`/api/admin/recovery/${requestId}/approve`).set("Authorization", admin1.auth)
    expect(first.status).toBe(200)
    expect(first.body.data.status).toBe("pending")
    expect((await request(app).post(`/api/admin/recovery/${requestId}/approve`).set("Authorization", admin1.auth)).status).toBe(409)
    expect((await login(newDid, newKey.privateKeyPem)).status).toBe(404)
  })

  it("second admin completes the rotation: new key signs in, old sessions stop, old signatures still verify", async () => {
    const second = await request(app).post(`/api/admin/recovery/${requestId}/approve`).set("Authorization", admin2.auth)
    expect(second.status).toBe(200)
    expect(second.body.data.status).toBe("completed")

    const ok = await login(newDid, newKey.privateKeyPem)
    expect(ok.status).toBe(200)
    expect(ok.body.data.user.did).toBe(newDid)
    expect(ok.body.data.user.previousDids.map((d: any) => d.did)).toEqual([officer.user.did])

    expect((await request(app).get("/api/evidence").set("Authorization", officer.auth)).status).toBe(401)
    expect((await login(officer.user.did, officer.privateKeyPem)).status).toBe(404)

    const verify = await request(app).get(`/api/evidence/${oldEvidence}/verify`).set("Authorization", judge.auth)
    expect(verify.body.data.checks.find((c: any) => c.name === "Uploader signature valid").ok).toBe(true)
    const oldDoc = await request(app).get(`/api/did/${encodeURIComponent(officer.user.did)}`)
    expect(oldDoc.body.current).toBe(false)
    expect(oldDoc.body.currentDid).toBe(newDid)

    const log = await request(app).get(`/api/audit-log?caseId=IDENTITY-REGISTRY&evidenceId=${encodeURIComponent(officer.user.did)}`).set("Authorization", admin3.auth)
    expect(log.body.data.map((r: any) => r.action).sort()).toEqual(expect.arrayContaining(["recovery_requested", "recovery_approved", "recovery_approved", "did_rotated"]))
  })

  it("case ownership follows the person to the new DID (restricted case access)", async () => {
    process.env.CASE_ACCESS_MODE = "restricted"
    try {
      const ok = await login(newDid, newKey.privateKeyPem)
      const auth = `Bearer ${ok.body.data.token}`
      expect((await request(app).get(`/api/evidence/${oldEvidence}/view`).set("Authorization", auth)).status).toBe(200)
      const cases = await request(app).get("/api/cases").set("Authorization", auth)
      expect(cases.body.data.find((c: any) => c.caseId === "CASE-REC")?.access).toBe("owner")
    } finally {
      process.env.CASE_ACCESS_MODE = "open"
    }
  })

  it("an admin cannot approve recovery of their own account", async () => {
    const r = await request(app).post("/api/recovery/request").send({ email: admin3.user.email, newPublicKeyHex: generateEd25519KeyPair().publicKeyHex })
    expect(r.status).toBe(201)
    const self = await request(app).post(`/api/admin/recovery/${r.body.data.id}/approve`).set("Authorization", admin3.auth)
    expect(self.status).toBe(403)
    const rej = await request(app).post(`/api/admin/recovery/${r.body.data.id}/reject`).set("Authorization", admin1.auth)
    expect(rej.body.data.status).toBe("rejected")
  })
})
