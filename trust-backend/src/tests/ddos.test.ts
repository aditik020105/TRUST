import request from "supertest"
import express from "express"
import {
  ddosMiddleware,
  resetDdosStore,
  stopCleanupTimer,
  cleanupStaleIps,
  getClientRecord,
  WINDOW_MS,
  MAX_REQUESTS,
  BAN_THRESHOLD,
  BAN_DURATION_MS
} from "../middleware/ddos.middleware"
import { errorMiddleware } from "../middleware/error.middleware"

describe("DDoS Protection Middleware", () => {
  let app: express.Express

  beforeEach(() => {
    resetDdosStore()
    app = express()
    app.use(ddosMiddleware)
    app.use(express.json({ limit: "2mb" }))

    app.get("/health", (req, res) => {
      res.json({ success: true, message: "TRUST backend is running" })
    })

    app.get("/ping", (req, res) => {
      res.status(200).send("OK")
    })

    app.get("/api/evidence", (req, res) => {
      res.json({ success: true, data: [] })
    })

    app.post("/api/evidence", (req, res) => {
      res.status(201).json({ success: true, data: req.body })
    })

    app.use(errorMiddleware)
  })

  afterAll(() => {
    stopCleanupTimer()
    resetDdosStore()
  })

  describe("Normal Traffic (Under Limits)", () => {
    it("allows a standard request and attaches RFC 6585 headers", async () => {
      const res = await request(app)
        .get("/api/evidence")
        .set("X-Forwarded-For", "10.0.0.1")

      expect(res.status).toBe(200)
      expect(res.body.success).toBe(true)
      expect(res.headers["x-ratelimit-limit"]).toBe(String(MAX_REQUESTS))
      expect(res.headers["x-ratelimit-remaining"]).toBe(String(MAX_REQUESTS - 1))
      expect(res.headers["x-ratelimit-reset"]).toBeDefined()
      expect(res.headers["x-ddos-protection"]).toBe("ACTIVE")
    })

    it("allows up to MAX_REQUESTS (30) within the window", async () => {
      const ip = "10.0.0.2"
      for (let i = 1; i <= MAX_REQUESTS; i++) {
        const res = await request(app)
          .get("/api/evidence")
          .set("X-Forwarded-For", ip)

        expect(res.status).toBe(200)
        expect(res.headers["x-ratelimit-remaining"]).toBe(String(MAX_REQUESTS - i))
      }
    })
  })

  describe("Rate Limit Enforcement (Burst Protection)", () => {
    it("rejects request 31 with HTTP 429 and standard error payload", async () => {
      const ip = "10.0.0.3"

      // Send 30 valid requests
      for (let i = 0; i < MAX_REQUESTS; i++) {
        const res = await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
        expect(res.status).toBe(200)
      }

      // The 31st request must trigger 429
      const blockedRes = await request(app)
        .get("/api/evidence")
        .set("X-Forwarded-For", ip)

      expect(blockedRes.status).toBe(429)
      expect(blockedRes.body).toEqual({
        success: false,
        error: "Too Many Requests - DDoS Protection Triggered",
        message: "Rate limit exceeded. Your IP has been temporarily throttled.",
        retryAfterSeconds: expect.any(Number)
      })
      expect(blockedRes.headers["retry-after"]).toBeDefined()
      expect(blockedRes.headers["x-ratelimit-remaining"]).toBe("0")
      expect(blockedRes.headers["x-ddos-protection"]).toBe("ACTIVE")
    })
  })

  describe("Flood Jail / Ban Threshold", () => {
    it("places IP into 30-second jail when request count exceeds BAN_THRESHOLD (50)", async () => {
      const ip = "10.0.0.4"

      // Send 50 requests
      for (let i = 0; i < BAN_THRESHOLD; i++) {
        await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      }

      // Request 51 exceeds BAN_THRESHOLD (50) and triggers jail
      const banRes = await request(app)
        .get("/api/evidence")
        .set("X-Forwarded-For", ip)

      expect(banRes.status).toBe(429)
      expect(banRes.body.success).toBe(false)
      expect(banRes.body.error).toBe("Too Many Requests - DDoS Protection Triggered")
      expect(banRes.body.retryAfterSeconds).toBeGreaterThanOrEqual(29)
      expect(banRes.body.retryAfterSeconds).toBeLessThanOrEqual(30)

      // Record should now have bannedUntil set
      const record = getClientRecord(ip)
      expect(record).toBeDefined()
      expect(record?.bannedUntil).toBeDefined()

      // Subsequent requests hit jail check immediately
      const jailedRes = await request(app)
        .get("/api/evidence")
        .set("X-Forwarded-For", ip)

      expect(jailedRes.status).toBe(429)
      expect(jailedRes.headers["x-ratelimit-remaining"]).toBe("0")
    })

    it("releases IP from jail after BAN_DURATION_MS expires", async () => {
      const ip = "10.0.0.40"
      const baseTime = 1000000000000
      const dateSpy = jest.spyOn(Date, "now").mockReturnValue(baseTime)

      // Flood to trigger jail
      for (let i = 0; i < BAN_THRESHOLD + 1; i++) {
        await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      }

      // Verify currently jailed
      const jailedRes = await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      expect(jailedRes.status).toBe(429)

      // Advance time past BAN_DURATION_MS
      dateSpy.mockReturnValue(baseTime + BAN_DURATION_MS + 1000)

      // Request after jail expiration should be allowed
      const releasedRes = await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      expect(releasedRes.status).toBe(200)

      dateSpy.mockRestore()
    })
  })

  describe("Endpoint Exemptions (/health and /ping)", () => {
    it("never throttles /health even when IP is already rate limited or banned", async () => {
      const ip = "10.0.0.5"

      // Flood the API to trigger jail
      for (let i = 0; i < BAN_THRESHOLD + 2; i++) {
        await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      }

      // Evidence route is throttled
      const evidenceRes = await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      expect(evidenceRes.status).toBe(429)

      // /health must remain accessible
      const healthRes = await request(app).get("/health").set("X-Forwarded-For", ip)
      expect(healthRes.status).toBe(200)
      expect(healthRes.body.success).toBe(true)
      expect(healthRes.body.message).toBe("TRUST backend is running")
    })

    it("never throttles /ping", async () => {
      const ip = "10.0.0.6"
      for (let i = 0; i < 40; i++) {
        const res = await request(app).get("/ping").set("X-Forwarded-For", ip)
        expect(res.status).toBe(200)
        expect(res.text).toBe("OK")
      }
    })

    it("exempts /HEALTH and /PING case-insensitively and with trailing slashes", async () => {
      const ip = "10.0.0.8"
      for (let i = 0; i < BAN_THRESHOLD + 1; i++) {
        await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      }

      const resHealth = await request(app).get("/HEALTH").set("X-Forwarded-For", ip)
      expect(resHealth.status).toBe(200)

      const resPing = await request(app).get("/PING/").set("X-Forwarded-For", ip)
      expect(resPing.status).toBe(200)
    })

    it("does not count /health requests towards protected endpoint quotas", async () => {
      const ip = "10.0.0.7"

      // Send 40 health requests
      for (let i = 0; i < 40; i++) {
        await request(app).get("/health").set("X-Forwarded-For", ip)
      }

      // API request should still have full quota
      const res = await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      expect(res.status).toBe(200)
      expect(res.headers["x-ratelimit-remaining"]).toBe(String(MAX_REQUESTS - 1))
    })
  })

  describe("Per-Client IP Isolation", () => {
    it("ensures throttling IP A does not impact legitimate requests from IP B", async () => {
      const ipA = "192.168.1.100"
      const ipB = "192.168.1.200"

      // Exhaust IP A's limit
      for (let i = 0; i < MAX_REQUESTS + 1; i++) {
        await request(app).get("/api/evidence").set("X-Forwarded-For", ipA)
      }

      // IP A is throttled
      const resA = await request(app).get("/api/evidence").set("X-Forwarded-For", ipA)
      expect(resA.status).toBe(429)

      // IP B should pass without restriction
      const resB = await request(app).get("/api/evidence").set("X-Forwarded-For", ipB)
      expect(resB.status).toBe(200)
      expect(resB.headers["x-ratelimit-remaining"]).toBe(String(MAX_REQUESTS - 1))
    })

    it("correctly extracts client IP from proxy chains in X-Forwarded-For", async () => {
      const res = await request(app)
        .get("/api/evidence")
        .set("X-Forwarded-For", "203.0.113.195, 70.41.3.18, 150.172.238.178")

      expect(res.status).toBe(200)
      const record = getClientRecord("203.0.113.195")
      expect(record).toBeDefined()
    })
  })

  describe("Payload Size Protection (Body Parser Limit)", () => {
    it("rejects JSON body payloads exceeding 2MB with HTTP 413", async () => {
      const largePayload = { data: "x".repeat(2.5 * 1024 * 1024) }
      const res = await request(app)
        .post("/api/evidence")
        .set("Content-Type", "application/json")
        .send(largePayload)

      expect(res.status).toBe(413)
      expect(res.body.success).toBe(false)
    })
  })

  describe("Cleanup and Stale Entries", () => {
    it("cleans up expired IP records to prevent memory leaks", async () => {
      const ip = "10.0.0.99"

      // Send request to create an entry
      await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      expect(getClientRecord(ip)).toBeDefined()

      // Calling cleanup immediately retains the active record
      cleanupStaleIps(Date.now())
      expect(getClientRecord(ip)).toBeDefined()

      // Calling cleanup after window elapsed prunes the record
      const futureTime = Date.now() + WINDOW_MS + 1000
      cleanupStaleIps(futureTime)
      expect(getClientRecord(ip)).toBeUndefined()
    })

    it("retains jailed IPs during cleanup until their ban expires", async () => {
      const ip = "10.0.0.100"

      // Trigger flood jail
      for (let i = 0; i < BAN_THRESHOLD + 1; i++) {
        await request(app).get("/api/evidence").set("X-Forwarded-For", ip)
      }
      expect(getClientRecord(ip)?.bannedUntil).toBeDefined()

      // Advance past windowMs but before banDurationMs
      const halfwayTime = Date.now() + WINDOW_MS + 1000
      cleanupStaleIps(halfwayTime)
      // IP must still be tracked because it is serving jail time
      expect(getClientRecord(ip)).toBeDefined()
    })
  })
})


describe("Repeat-abuse DID revocation", () => {
  // Uses the real app so the firewall can identify the caller from a verified session token.
  const { app: realApp } = require("../index")
  const { createActor } = require("./support/helpers")
  const { flushFirewallTasks, STRIKES_BEFORE_REVOCATION } = require("../middleware/ddos.middleware")
  const { userService } = require("../services/user.service")

  async function flood(auth: string | null, ip: string) {
    resetDdosStore()
    for (let i = 0; i <= BAN_THRESHOLD; i++) {
      const r = request(realApp).get("/api/evidence").set("X-Forwarded-For", ip)
      await (auth ? r.set("Authorization", auth) : r)
    }
    await flushFirewallTasks()
  }

  it(`revokes a user's DID after ${3} flood jails and records it on the ledger`, async () => {
    expect(STRIKES_BEFORE_REVOCATION).toBe(3)
    const abuser = await createActor("investigator")
    await flood(abuser.auth, "10.9.9.1")
    expect((await userService.getUserByUid(abuser.user.uid)).firewallWarnings).toBe(1)
    expect((await userService.getUserByUid(abuser.user.uid)).status).toBe("approved")
    await flood(abuser.auth, "10.9.9.2")
    await flood(abuser.auth, "10.9.9.3")
    const after = await userService.getUserByUid(abuser.user.uid)
    expect(after.status).toBe("revoked")
    expect(after.authorizedBy).toBe("did:trust:system:gateway")

    resetDdosStore()
    const res = await request(realApp).get("/api/evidence").set("Authorization", abuser.auth).set("X-Forwarded-For", "10.9.9.4")
    expect(res.status).toBe(403)
  })

  it("does not count floods with a forged token against anyone", async () => {
    const victim = await createActor("analyst")
    const enc = (o: any) => Buffer.from(JSON.stringify(o)).toString("base64url")
    const forged = `Bearer ${enc({ alg: "HS256" })}.${enc({ sub: victim.user.uid, did: victim.user.did })}.${enc("x")}`
    await flood(forged, "10.9.9.5")
    expect((await userService.getUserByUid(victim.user.uid)).firewallWarnings).toBe(0)
  })
})
