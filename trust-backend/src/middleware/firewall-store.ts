/**
 * Where the firewall keeps its counters.
 *
 * - MemoryFirewallStore: per process (default). Fine for one backend instance.
 * - RedisFirewallStore (REDIS_URL set): shared by every backend instance, so a client cannot
 *   dodge the limit by spreading requests across instances. Each hit is one atomic Lua script
 *   (sliding window in a sorted set + jail key with TTL), so concurrent instances never race.
 */

export interface FirewallParams { windowMs: number; banThreshold: number; banMs: number }

export interface HitResult {
  /** epoch ms the client is jailed until, 0 if not jailed */
  bannedUntil: number
  /** requests in the current window (including this one unless already jailed) */
  count: number
  /** timestamp of the oldest request in the window */
  oldest: number
  /** true only on the request that triggered the jail */
  newlyJailed: boolean
  /** true if the client was already in jail before this request */
  alreadyJailed: boolean
}

export interface ClientSnapshot { ip: string; count: number; bannedUntil: number }

export interface FirewallLogEntryBase {
  id: string
  timestamp: string
  status: number
  [k: string]: any
}

export interface FirewallStore {
  readonly kind: "memory" | "redis"
  hit(ip: string, now: number, p: FirewallParams): Promise<HitResult>
  unban(ip: string): Promise<boolean>
  reset(): Promise<void>
  snapshot(now: number, p: FirewallParams): Promise<ClientSnapshot[]>
  pushLog(entry: FirewallLogEntryBase, max: number): Promise<void>
  logs(limit: number): Promise<FirewallLogEntryBase[]>
}

// ---------------------------------------------------------------------------
export interface ClientRecord { timestamps: number[]; bannedUntil?: number }

export class MemoryFirewallStore implements FirewallStore {
  readonly kind = "memory" as const
  readonly clients = new Map<string, ClientRecord>()
  private entries: FirewallLogEntryBase[] = []

  /** Synchronous core, shared by hit() and the unit tests. */
  hitSync(ip: string, now: number, p: FirewallParams): HitResult {
    let client = this.clients.get(ip)
    if (client?.bannedUntil) {
      if (client.bannedUntil > now) {
        return { bannedUntil: client.bannedUntil, count: client.timestamps.length, oldest: client.timestamps[0] || now, newlyJailed: false, alreadyJailed: true }
      }
      client.bannedUntil = undefined
      client.timestamps = []
    }
    if (!client) {
      client = { timestamps: [] }
      this.clients.set(ip, client)
    }
    client.timestamps = client.timestamps.filter(t => t > now - p.windowMs)
    client.timestamps.push(now)
    const count = client.timestamps.length
    if (count > p.banThreshold) {
      client.bannedUntil = now + p.banMs
      return { bannedUntil: client.bannedUntil, count, oldest: client.timestamps[0], newlyJailed: true, alreadyJailed: false }
    }
    return { bannedUntil: 0, count, oldest: client.timestamps[0], newlyJailed: false, alreadyJailed: false }
  }

  async hit(ip: string, now: number, p: FirewallParams) { return this.hitSync(ip, now, p) }

  async unban(ip: string) { return this.clients.delete(ip) }

  async reset() {
    this.clients.clear()
    this.entries.length = 0
  }

  cleanup(now: number, windowMs: number) {
    for (const [ip, c] of this.clients) {
      if (c.bannedUntil && c.bannedUntil > now) continue
      if (c.bannedUntil && c.bannedUntil <= now) c.bannedUntil = undefined
      c.timestamps = c.timestamps.filter(t => t > now - windowMs)
      if (c.timestamps.length === 0) this.clients.delete(ip)
    }
  }

  async snapshot(now: number, p: FirewallParams) {
    return Array.from(this.clients.entries()).map(([ip, r]) => ({
      ip,
      count: r.timestamps.filter(t => t > now - p.windowMs).length,
      bannedUntil: r.bannedUntil && r.bannedUntil > now ? r.bannedUntil : 0
    }))
  }

  async pushLog(entry: FirewallLogEntryBase, max: number) {
    this.entries.unshift(entry)
    if (this.entries.length > max) this.entries.length = max
  }

  async logs(limit: number) { return this.entries.slice(0, limit) }
}

// ---------------------------------------------------------------------------
const HIT_SCRIPT = `
local tsKey, banKey, ipsKey = KEYS[1], KEYS[2], KEYS[3]
local now, window, threshold, banMs = tonumber(ARGV[1]), tonumber(ARGV[2]), tonumber(ARGV[3]), tonumber(ARGV[4])
local member, ip = ARGV[5], ARGV[6]
redis.call('ZADD', ipsKey, now, ip)
local ban = redis.call('GET', banKey)
if ban and tonumber(ban) > now then
  local first = redis.call('ZRANGE', tsKey, 0, 0, 'WITHSCORES')
  return {ban, tostring(redis.call('ZCARD', tsKey)), first[2] or tostring(now), '0', '1'}
end
if ban then
  redis.call('DEL', banKey)
  redis.call('DEL', tsKey)
end
redis.call('ZREMRANGEBYSCORE', tsKey, '-inf', now - window)
redis.call('ZADD', tsKey, now, member)
redis.call('PEXPIRE', tsKey, window + banMs)
local count = redis.call('ZCARD', tsKey)
local first = redis.call('ZRANGE', tsKey, 0, 0, 'WITHSCORES')
if count > threshold then
  local untilMs = now + banMs
  redis.call('SET', banKey, tostring(untilMs), 'PX', banMs)
  return {tostring(untilMs), tostring(count), first[2], '1', '0'}
end
return {'0', tostring(count), first[2], '0', '0'}
`

export class RedisFirewallStore implements FirewallStore {
  readonly kind = "redis" as const
  private client: any
  private ready: Promise<void>
  private prefix: string

  constructor(url: string, prefix = process.env.REDIS_PREFIX || "trust:fw:") {
    const { createClient } = require("redis")
    this.prefix = prefix
    this.client = createClient({ url })
    this.client.on("error", (err: any) => console.error("[firewall] redis error:", err?.message || err))
    this.ready = this.client.connect().then(() => undefined)
  }

  private k(...parts: string[]) { return this.prefix + parts.join(":") }

  async hit(ip: string, now: number, p: FirewallParams): Promise<HitResult> {
    await this.ready
    const member = `${now}-${Math.random().toString(36).slice(2, 10)}`
    const r: string[] = await this.client.eval(HIT_SCRIPT, {
      keys: [this.k("ts", ip), this.k("ban", ip), this.k("ips")],
      arguments: [String(now), String(p.windowMs), String(p.banThreshold), String(p.banMs), member, ip]
    })
    return {
      bannedUntil: Number(r[0]),
      count: Number(r[1]),
      oldest: Number(r[2]),
      newlyJailed: r[3] === "1",
      alreadyJailed: r[4] === "1"
    }
  }

  async unban(ip: string) {
    await this.ready
    const n = await this.client.del([this.k("ts", ip), this.k("ban", ip)])
    await this.client.zRem(this.k("ips"), ip)
    return n > 0
  }

  async reset() {
    await this.ready
    const keys: string[] = []
    for await (const key of this.client.scanIterator({ MATCH: `${this.prefix}*`, COUNT: 500 })) keys.push(key)
    if (keys.length) await this.client.del(keys)
  }

  async snapshot(now: number, p: FirewallParams) {
    await this.ready
    await this.client.zRemRangeByScore(this.k("ips"), "-inf", now - p.windowMs - p.banMs)
    const ips: string[] = await this.client.zRange(this.k("ips"), 0, -1)
    const out: ClientSnapshot[] = []
    for (const ip of ips) {
      const [count, ban] = await Promise.all([
        this.client.zCount(this.k("ts", ip), now - p.windowMs, "+inf"),
        this.client.get(this.k("ban", ip))
      ])
      const bannedUntil = ban && Number(ban) > now ? Number(ban) : 0
      if (count > 0 || bannedUntil) out.push({ ip, count, bannedUntil })
    }
    return out
  }

  async pushLog(entry: FirewallLogEntryBase, max: number) {
    await this.ready
    await this.client.multi().lPush(this.k("logs"), JSON.stringify(entry)).lTrim(this.k("logs"), 0, max - 1).exec()
  }

  async logs(limit: number) {
    await this.ready
    const raw: string[] = await this.client.lRange(this.k("logs"), 0, limit - 1)
    return raw.map(r => JSON.parse(r))
  }

  async close() {
    try { await this.client.quit() } catch { /* ignore */ }
  }
}
