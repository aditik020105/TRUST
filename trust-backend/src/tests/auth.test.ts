import request from "supertest"
import jwt from "jsonwebtoken"
import { app } from "../index"
import { createActor } from "./support/helpers"
import { generateEd25519KeyPair, signWithPrivateKeyPem, signingPayloads } from "../services/did.service"
import { __setFirebaseVerifier } from "../services/auth.service"
import { resetDdosStore, stopCleanupTimer } from "../middleware/ddos.middleware"

beforeEach(() => resetDdosStore())
afterAll(() => stopCleanupTimer())

async function register(email: string, extra: Record<string, any> = {}) {
  const keys = generateEd25519KeyPair()
  const res = await request(app).post("/api/users/register").send({ email, displayName: "T", requestedRole: "analyst", publicKeyHex: keys.publicKeyHex, ...extra })
  return { res, keys }
}

async function login(email: string, privateKeyPem: string) {
  const ch = await request(app).post("/api/auth/challenge").send({ email })
  const sig = signWithPrivateKeyPem(privateKeyPem, ch.body.data.payload)
  return request(app).post("/api/auth/verify").send({ did: ch.body.data.did, nonce: ch.body.data.nonce, signatureHex: sig })
}

describe("Session tokens", () => {
  it("rejects requests with no token (no dev fallback identity)", async () => {
    const res = await request(app).get("/api/evidence")
    expect(res.status).toBe(401)
    expect(res.body.code).toBe("AUTH_REQUIRED")
  })

  it("rejects a forged, unsigned token like the one the old dashboard built", async () => {
    const enc = (o: any) => Buffer.from(JSON.stringify(o)).toString("base64url")
    const forged = `${enc({ alg: "EdDSA" })}.${enc({ sub: "x", role: "admin", did: "did:trust:admin01", status: "approved" })}.${enc("sig")}`
    const res = await request(app).get("/api/evidence").set("Authorization", `Bearer ${forged}`)
    expect(res.status).toBe(401)
    expect(res.body.code).toBe("TOKEN_INVALID")
  })

  it("rejects an expired token", async () => {
    const a = await createActor("investigator")
    const expired = jwt.sign({ did: a.user.did }, process.env.JWT_SECRET!, {
      subject: a.user.uid, expiresIn: -10, issuer: "trust-backend", audience: "trust-dashboard"
    })
    const res = await request(app).get("/api/evidence").set("Authorization", `Bearer ${expired}`)
    expect(res.status).toBe(401)
    expect(res.body.code).toBe("TOKEN_EXPIRED")
  })

  it("takes role and status from the registry, not from token claims", async () => {
    const a = await createActor("investigator")
    const lying = jwt.sign({ did: a.user.did, role: "admin" }, process.env.JWT_SECRET!, {
      subject: a.user.uid, expiresIn: 60, issuer: "trust-backend", audience: "trust-dashboard"
    })
    const res = await request(app).get("/api/admin/users").set("Authorization", `Bearer ${lying}`)
    expect(res.status).toBe(403)
  })
})

describe("Registration", () => {
  it("always creates a pending account, ignoring initialStatus and admin role requests", async () => {
    const { res } = await register("self.approve@trust.test", { initialStatus: "approved", requestedRole: "admin" })
    expect(res.status).toBe(201)
    expect(res.body.data.status).toBe("pending")
    expect(res.body.data.role).toBe("investigator")
    expect(res.body.data.requestedRole).toBe("admin")
    expect(res.body.data.did).toMatch(/^did:trust:investigator:[0-9a-f]{16}$/)
    expect(res.body.data.didDocument.verificationMethod[0].type).toBe("Ed25519VerificationKey2020")
    expect(JSON.stringify(res.body)).not.toMatch(/PRIVATE KEY/)
  })

  it("approves the first ADMIN_EMAILS account as bootstrap admin, but only once", async () => {
    process.env.ADMIN_EMAILS = "boss@trust.test,boss2@trust.test"
    try {
      const first = await register("boss@trust.test")
      expect(first.res.body.data.role).toBe("admin")
      expect(first.res.body.data.status).toBe("approved")
      const second = await register("boss2@trust.test")
      expect(second.res.body.data.status).toBe("pending")
    } finally {
      delete process.env.ADMIN_EMAILS
    }
  })

  it("rejects duplicate emails and invalid public keys", async () => {
    await register("dup@trust.test")
    const again = await register("dup@trust.test")
    expect(again.res.status).toBe(409)
    const bad = await request(app).post("/api/users/register").send({ email: "bad@trust.test", publicKeyHex: "1234" })
    expect(bad.status).toBe(400)
  })

  it("has no server-side signing endpoint", async () => {
    const res = await request(app).post("/api/did/sign").send({ did: "did:trust:x", payload: "p" })
    expect(res.status).toBe(404)
  })
})

describe("DID challenge-response login", () => {
  it("issues a session token for a valid signature over the one-time nonce", async () => {
    const { keys } = await register("login.ok@trust.test")
    const res = await login("login.ok@trust.test", keys.privateKeyPem)
    expect(res.status).toBe(200)
    expect(res.body.data.token).toBeTruthy()
    expect(new Date(res.body.data.expiresAt).getTime()).toBeGreaterThan(Date.now())
    const me = await request(app).get("/api/users/me").set("Authorization", `Bearer ${res.body.data.token}`)
    expect(me.status).toBe(200)
    expect(me.body.data.email).toBe("login.ok@trust.test")
  })

  it("rejects a signature made with a different key (impersonation)", async () => {
    await register("victim@trust.test")
    const attacker = generateEd25519KeyPair()
    const res = await login("victim@trust.test", attacker.privateKeyPem)
    expect(res.status).toBe(401)
    expect(res.body.code).toBe("SIGNATURE_INVALID")
  })

  it("rejects a replayed challenge", async () => {
    const { keys } = await register("replay@trust.test")
    const ch = await request(app).post("/api/auth/challenge").send({ email: "replay@trust.test" })
    const body = { did: ch.body.data.did, nonce: ch.body.data.nonce, signatureHex: signWithPrivateKeyPem(keys.privateKeyPem, ch.body.data.payload) }
    expect((await request(app).post("/api/auth/verify").send(body)).status).toBe(200)
    const replay = await request(app).post("/api/auth/verify").send(body)
    expect(replay.status).toBe(401)
    expect(replay.body.code).toBe("CHALLENGE_INVALID")
  })

  it("requires a matching Firebase ID token when Firebase is enabled", async () => {
    process.env.FIREBASE_PROJECT_ID = "trust-test"
    __setFirebaseVerifier(async (t: string) => {
      if (t === "good-token") return { uid: "fb-uid-1", email: "fb@trust.test" }
      throw new Error("bad token")
    })
    try {
      const keys = generateEd25519KeyPair()
      const noToken = await request(app).post("/api/users/register").send({ email: "fb@trust.test", publicKeyHex: keys.publicKeyHex })
      expect(noToken.status).toBe(401)
      const reg = await request(app).post("/api/users/register").send({ email: "fb@trust.test", publicKeyHex: keys.publicKeyHex, firebaseIdToken: "good-token" })
      expect(reg.status).toBe(201)
      expect(reg.body.data.uid).toBe("fb-uid-1")

      const ch = await request(app).post("/api/auth/challenge").send({ email: "fb@trust.test" })
      expect(ch.body.data.firebaseRequired).toBe(true)
      const sig = signWithPrivateKeyPem(keys.privateKeyPem, signingPayloads.login(ch.body.data.did, ch.body.data.nonce))
      const without = await request(app).post("/api/auth/verify").send({ did: ch.body.data.did, nonce: ch.body.data.nonce, signatureHex: sig })
      expect(without.status).toBe(401)

      const ch2 = await request(app).post("/api/auth/challenge").send({ email: "fb@trust.test" })
      const sig2 = signWithPrivateKeyPem(keys.privateKeyPem, ch2.body.data.payload)
      const ok = await request(app).post("/api/auth/verify").send({ did: ch2.body.data.did, nonce: ch2.body.data.nonce, signatureHex: sig2, firebaseIdToken: "good-token" })
      expect(ok.status).toBe(200)
    } finally {
      delete process.env.FIREBASE_PROJECT_ID
      __setFirebaseVerifier(null)
    }
  })
})
