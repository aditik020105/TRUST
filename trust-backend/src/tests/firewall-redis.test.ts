import request from "supertest"
import express from "express"
import { RedisFirewallStore } from "../middleware/firewall-store"
import { ddosMiddleware, useFirewallStore, getFirewallTelemetry, MAX_REQUESTS, BAN_THRESHOLD, stopCleanupTimer } from "../middleware/ddos.middleware"

// Runs only when a Redis server is available: REDIS_TEST_URL=redis://127.0.0.1:6379 npx jest firewall-redis
const url = process.env.REDIS_TEST_URL
const d = url ? describe : describe.skip

d("Firewall state shared through Redis (multiple backend instances)", () => {
  const params = { windowMs: 10000, banThreshold: BAN_THRESHOLD, banMs: 30000 }
  let a: RedisFirewallStore, b: RedisFirewallStore

  beforeAll(async () => {
    a = new RedisFirewallStore(url!, `trust:test:${Date.now()}:`)
    b = new RedisFirewallStore(url!, (a as any).prefix)
    await a.reset()
  })
  afterAll(async () => {
    await a.reset()
    await a.close()
    await b.close()
    useFirewallStore(null)
    stopCleanupTimer()
  })

  it("counts requests from one client across two instances in the same window", async () => {
    const now = Date.now()
    for (let i = 0; i < 20; i++) await a.hit("198.51.100.1", now + i, params)
    const r = await b.hit("198.51.100.1", now + 25, params)
    expect(r.count).toBe(21)
  })

  it("a jail set by one instance is enforced by the other", async () => {
    const now = Date.now()
    let last
    for (let i = 0; i <= BAN_THRESHOLD; i++) last = await a.hit("198.51.100.2", now + i, params)
    expect(last!.newlyJailed).toBe(true)
    const other = await b.hit("198.51.100.2", now + 100, params)
    expect(other.alreadyJailed).toBe(true)
    expect(other.bannedUntil).toBe(last!.bannedUntil)
    // after the jail expires both instances let the client back in
    const later = await b.hit("198.51.100.2", last!.bannedUntil + 1, params)
    expect(later.alreadyJailed).toBe(false)
    expect(later.count).toBe(1)
  })

  it("concurrent hits from many instances are counted exactly (atomic script)", async () => {
    const now = Date.now()
    await Promise.all(Array.from({ length: 40 }, (_, i) => (i % 2 ? a : b).hit("198.51.100.3", now + i, params)))
    const r = await a.hit("198.51.100.3", now + 50, params)
    expect(r.count).toBe(41)
  })

  it("the middleware throttles at MAX_REQUESTS using the shared store, and telemetry reads it back", async () => {
    useFirewallStore(a)
    const app1 = express().use(ddosMiddleware).get("/api/x", (_req, res) => res.json({ ok: true }))
    useFirewallStore(b)
    const app2 = express().use(ddosMiddleware).get("/api/x", (_req, res) => res.json({ ok: true }))
    process.env.TRUST_PROXY = "true"
    const ip = "198.51.100.4"
    for (let i = 0; i < MAX_REQUESTS; i++) {
      const r = await request(i % 2 ? app1 : app2).get("/api/x").set("X-Forwarded-For", ip)
      expect(r.status).toBe(200)
    }
    const blocked = await request(app1).get("/api/x").set("X-Forwarded-For", ip)
    expect(blocked.status).toBe(429)
    const t = await getFirewallTelemetry()
    expect(t.parameters.STORE).toBe("redis")
    expect(t.activeClients.find((c: any) => c.ip === ip)?.requestsInWindow).toBe(MAX_REQUESTS + 1)
    expect(t.rejectedLogs.length).toBeGreaterThan(0)
  })
})
