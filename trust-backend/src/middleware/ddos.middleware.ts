import { Request, Response, NextFunction } from "express"
import { verifySessionToken } from "../services/auth.service"
import { userService, SYSTEM_DID } from "../services/user.service"
import { FirewallStore, MemoryFirewallStore, RedisFirewallStore, ClientRecord } from "./firewall-store"
export type { ClientRecord }

// Defaults match the paper (30 req / 10 s, jail above 50 for 30 s). Raise them for clients that
// share one IP (e.g. a whole station behind NAT) via environment variables.
const envInt = (name: string, def: number) => {
  const n = Number(process.env[name])
  return Number.isFinite(n) && n > 0 ? n : def
}
export const WINDOW_MS = envInt("FIREWALL_WINDOW_MS", 10000)         // sliding window
export const MAX_REQUESTS = envInt("FIREWALL_MAX_REQUESTS", 30)      // requests allowed per window
export const BAN_THRESHOLD = envInt("FIREWALL_BAN_THRESHOLD", 50)    // requests above this trigger jail
export const BAN_DURATION_MS = envInt("FIREWALL_BAN_MS", 30000)      // jail duration
export const CLEANUP_INTERVAL_MS = 30000 // Automatic stale IP cleanup interval
export const STRIKES_BEFORE_REVOCATION = Number(process.env.FIREWALL_STRIKES || 3) // jail events per user before DID revocation

export interface FirewallLogEntry {
  id: string
  ip: string
  method: string
  path: string
  status: 200 | 429
  decision: "ALLOWED" | "THROTTLED_BURST" | "JAILED_FLOOD" | "USER_WARNING" | "DID_REVOKED"
  requestCountInWindow: number
  remainingQuota: number
  retryAfterSeconds?: number
  serverMessage: string
  timestamp: string
}

const MAX_FIREWALL_LOGS = 200
const PARAMS = { windowMs: WINDOW_MS, banThreshold: BAN_THRESHOLD, banMs: BAN_DURATION_MS }

// Counters live in Redis when REDIS_URL is set (shared by all backend instances), else in memory.
const memoryStore = new MemoryFirewallStore()
let store: FirewallStore = process.env.REDIS_URL ? new RedisFirewallStore(process.env.REDIS_URL) : memoryStore

export function firewallStoreKind(): "memory" | "redis" {
  return store.kind
}

/** Test hook: use a given store (e.g. Redis) or go back to memory. */
export function useFirewallStore(s: FirewallStore | null): void {
  store = s || memoryStore
}

function recordFirewallLog(entry: Omit<FirewallLogEntry, "id" | "timestamp">): void {
  const full = {
    ...entry,
    id: `FW-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
    timestamp: new Date().toISOString()
  }
  pendingTasks.push(store.pushLog(full, MAX_FIREWALL_LOGS).catch(err => console.error("[firewall] log write failed:", err?.message)))
}

// ---------------------------------------------------------------------------
// Repeat-abuse handling: each flood jail is a "warning" against the authenticated
// user (identified only from a verified session token, so nobody can get another
// user revoked by forging their DID). After STRIKES_BEFORE_REVOCATION warnings the
// user's DID is revoked through the identity registry, which records it on the ledger.
// ---------------------------------------------------------------------------
let pendingTasks: Promise<unknown>[] = []

/** Test helper: waits for background warning/revocation writes. */
export async function flushFirewallTasks(): Promise<void> {
  const tasks = pendingTasks
  pendingTasks = []
  await Promise.allSettled(tasks)
}

function identifyCaller(req: Request): { uid: string; did: string } | null {
  const h = req.headers.authorization
  if (!h || !h.startsWith("Bearer ")) return null
  try {
    const c = verifySessionToken(h.slice(7).trim())
    return { uid: c.sub, did: c.did }
  } catch {
    return null
  }
}

async function recordFloodWarning(caller: { uid: string; did: string }, ip: string, path: string): Promise<void> {
  const user = await userService.getUserByUid(caller.uid)
  if (!user || user.did !== caller.did || user.status === "revoked") return
  const warnings = (user.firewallWarnings || 0) + 1
  await userService.setFirewallWarnings(user.uid, warnings)

  if (warnings >= STRIKES_BEFORE_REVOCATION) {
    await userService.updateUserAuthorization({
      uid: user.uid,
      status: "revoked",
      adminDid: SYSTEM_DID,
      reason: `Adaptive firewall: ${warnings} flood jails (threshold ${STRIKES_BEFORE_REVOCATION})`
    })
    recordFirewallLog({
      ip, method: "-", path, status: 429, decision: "DID_REVOKED",
      requestCountInWindow: 0, remainingQuota: 0,
      serverMessage: `DID ${user.did} revoked after ${warnings} flood warnings; revocation committed to the ledger.`
    })
  } else {
    recordFirewallLog({
      ip, method: "-", path, status: 429, decision: "USER_WARNING",
      requestCountInWindow: 0, remainingQuota: 0,
      serverMessage: `Warning ${warnings}/${STRIKES_BEFORE_REVOCATION} recorded against ${user.did}.`
    })
  }
}

/**
 * Extracts client IP address with proxy support.
 */
export function getClientIp(req: Request): string {
  // X-Forwarded-For is client-controlled; only honour it behind a known reverse proxy,
  // otherwise an attacker could rotate fake IPs to dodge the limiter.
  if (process.env.TRUST_PROXY !== "true") {
    return req.ip || req.socket?.remoteAddress || "127.0.0.1"
  }
  const forwarded = req.headers["x-forwarded-for"]
  if (typeof forwarded === "string" && forwarded.trim().length > 0) {
    return forwarded.split(",")[0].trim()
  }
  if (Array.isArray(forwarded) && forwarded.length > 0 && typeof forwarded[0] === "string") {
    return forwarded[0].split(",")[0].trim()
  }
  return req.ip || req.socket?.remoteAddress || "127.0.0.1"
}

/**
 * Removes stale IP records whose requests are outside the sliding window
 * and are not currently serving a jail ban.
 */
export function cleanupStaleIps(now: number = Date.now()): void {
  memoryStore.cleanup(now, WINDOW_MS)
}

// Background cleanup timer (unref'd to prevent keeping the Node process/event loop alive)
let cleanupInterval: NodeJS.Timeout | null = setInterval(() => {
  cleanupStaleIps()
}, CLEANUP_INTERVAL_MS)

if (cleanupInterval && typeof cleanupInterval.unref === "function") {
  cleanupInterval.unref()
}

/**
 * Stops the cleanup timer (useful for test teardown).
 */
export function stopCleanupTimer(): void {
  if (cleanupInterval) {
    clearInterval(cleanupInterval)
    cleanupInterval = null
  }
}

/**
 * Clears all stored IP tracking data and logs (memory immediately; Redis asynchronously).
 */
export function resetDdosStore(): Promise<void> {
  pendingTasks = []
  const p = memoryStore.reset()
  return store === memoryStore ? p : store.reset()
}

/** Retrieves the in-memory tracking record for an IP (memory store only; for tests). */
export function getClientRecord(ip: string): ClientRecord | undefined {
  return memoryStore.clients.get(ip)
}

export function unbanClientIp(ip: string): Promise<boolean> {
  return store.unban(ip)
}

/** Live firewall parameters, client states and recent logs for the admin dashboard. */
export async function getFirewallTelemetry() {
  const now = Date.now()
  await flushFirewallTasks()
  const snapshot = await store.snapshot(now, PARAMS)
  const activeClients = snapshot.map(({ ip, count, bannedUntil }) => {
    const isBanned = bannedUntil > now
    return {
      ip,
      requestsInWindow: count,
      remainingQuota: isBanned ? 0 : Math.max(0, MAX_REQUESTS - count),
      status: isBanned ? "JAILED_BANNED" : count > MAX_REQUESTS ? "THROTTLED_429" : "ACTIVE_OK",
      bannedUntil: isBanned ? new Date(bannedUntil).toISOString() : null,
      retryAfterSeconds: isBanned ? Math.ceil((bannedUntil - now) / 1000) : 0
    }
  })
  const logs = (await store.logs(MAX_FIREWALL_LOGS)) as FirewallLogEntry[]
  return {
    parameters: { WINDOW_MS, MAX_REQUESTS, BAN_THRESHOLD, BAN_DURATION_MS, CLEANUP_INTERVAL_MS, STRIKES_BEFORE_REVOCATION, STORE: store.kind },
    activeClients,
    recentLogs: logs.slice(0, 100),
    rejectedLogs: logs.filter(l => l.status === 429).slice(0, 50)
  }
}

function reject(res: Response, retryAfterSeconds: number, resetTimestamp: number) {
  res.setHeader("Retry-After", String(retryAfterSeconds))
  res.setHeader("X-RateLimit-Limit", String(MAX_REQUESTS))
  res.setHeader("X-RateLimit-Remaining", "0")
  res.setHeader("X-RateLimit-Reset", String(resetTimestamp))
  res.setHeader("X-DDoS-Protection", "ACTIVE")
  res.status(429).json({
    success: false,
    error: "Too Many Requests - DDoS Protection Triggered",
    message: "Rate limit exceeded. Your IP has been temporarily throttled.",
    retryAfterSeconds
  })
}

/**
 * Sliding-window rate limiter and flood jail. Counters are kept by the configured store
 * (memory, or Redis shared across instances via one atomic script per request).
 */
export async function ddosMiddleware(req: Request, res: Response, next: NextFunction): Promise<void> {
  const rawPath = req.path || (req.originalUrl ? req.originalUrl.split("?")[0] : "")
  const normalizedPath = rawPath.toLowerCase().replace(/\/+$/, "") || "/"

  // /health and /ping stay reachable for monitoring; /api/admin/firewall so an admin can always inspect/reset
  if (
    normalizedPath === "/health" ||
    normalizedPath === "/ping" ||
    normalizedPath.startsWith("/health/") ||
    normalizedPath.startsWith("/ping/") ||
    normalizedPath.startsWith("/api/admin/firewall")
  ) {
    next()
    return
  }

  const clientIp = getClientIp(req)
  const now = Date.now()
  let hit
  try {
    hit = await store.hit(clientIp, now, PARAMS)
  } catch (err: any) {
    // Fail open on a store outage so the court can still reach its evidence; log loudly.
    console.error("[firewall] store unavailable, allowing request:", err?.message || err)
    next()
    return
  }

  // 1. Already jailed
  if (hit.alreadyJailed) {
    const retryAfterSeconds = Math.max(1, Math.ceil((hit.bannedUntil - now) / 1000))
    recordFirewallLog({
      ip: clientIp, method: req.method, path: normalizedPath, status: 429, decision: "JAILED_FLOOD",
      requestCountInWindow: hit.count, remainingQuota: 0, retryAfterSeconds,
      serverMessage: "Too Many Requests - DDoS Protection Triggered: Rate limit exceeded. Your IP has been temporarily throttled (Jailed)."
    })
    return reject(res, retryAfterSeconds, Math.ceil(hit.bannedUntil / 1000))
  }

  // 2. This request pushed the client over the flood threshold: jail, and warn the user behind it
  if (hit.newlyJailed) {
    const caller = identifyCaller(req)
    if (caller) {
      pendingTasks.push(
        recordFloodWarning(caller, clientIp, normalizedPath).catch(err =>
          console.error("[firewall] could not record warning/revocation:", err?.message || err)
        )
      )
    }
    const retryAfterSeconds = Math.ceil(BAN_DURATION_MS / 1000)
    recordFirewallLog({
      ip: clientIp, method: req.method, path: normalizedPath, status: 429, decision: "JAILED_FLOOD",
      requestCountInWindow: hit.count, remainingQuota: 0, retryAfterSeconds,
      serverMessage: `Flood Ban Triggered (${hit.count} > BAN_THRESHOLD=${BAN_THRESHOLD}): IP jailed for ${retryAfterSeconds}s.`
    })
    return reject(res, retryAfterSeconds, Math.ceil(hit.bannedUntil / 1000))
  }

  // 3. Over the per-window limit: throttle
  if (hit.count > MAX_REQUESTS) {
    const resetTimeMs = hit.oldest + WINDOW_MS
    const retryAfterSeconds = Math.max(1, Math.ceil((resetTimeMs - now) / 1000))
    recordFirewallLog({
      ip: clientIp, method: req.method, path: normalizedPath, status: 429, decision: "THROTTLED_BURST",
      requestCountInWindow: hit.count, remainingQuota: 0, retryAfterSeconds,
      serverMessage: `Rate Limit Exceeded (${hit.count} > MAX_REQUESTS=${MAX_REQUESTS} in ${WINDOW_MS / 1000}s window): Request rejected with HTTP 429.`
    })
    return reject(res, retryAfterSeconds, Math.ceil(resetTimeMs / 1000))
  }

  // 4. Allowed
  const remaining = Math.max(0, MAX_REQUESTS - hit.count)
  res.setHeader("X-RateLimit-Limit", String(MAX_REQUESTS))
  res.setHeader("X-RateLimit-Remaining", String(remaining))
  res.setHeader("X-RateLimit-Reset", String(Math.ceil((hit.oldest + WINDOW_MS) / 1000)))
  res.setHeader("X-DDoS-Protection", "ACTIVE")
  recordFirewallLog({
    ip: clientIp, method: req.method, path: normalizedPath, status: 200, decision: "ALLOWED",
    requestCountInWindow: hit.count, remainingQuota: remaining,
    serverMessage: `Allowed (${hit.count}/${MAX_REQUESTS} in window, ${remaining} remaining)`
  })
  next()
}
