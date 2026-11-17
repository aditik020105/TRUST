import { createClient } from "@supabase/supabase-js"
import fs from "fs"
import path from "path"

/**
 * Database + object storage client.
 *
 * - When SUPABASE_URL and SUPABASE_SERVICE_KEY are set, the real Supabase client is used
 *   (Postgres tables from supabase/schema.sql and the private "evidence-files" bucket).
 * - Otherwise a small file-backed emulator with the same query surface is used, so the
 *   backend runs offline / air-gapped and in tests. Data lives in $DATA_DIR/db.json and
 *   $STORAGE_DIR/<bucket>/...
 */

export const EVIDENCE_BUCKET = process.env.SUPABASE_BUCKET || "evidence-files"

function isConfigured(val?: string): boolean {
  if (!val) return false
  const lower = val.toLowerCase().trim()
  return !(lower === "" || lower === "undefined" || lower.includes("your-") || lower.includes("placeholder"))
}

const supabaseUrl = process.env.SUPABASE_URL
const supabaseKey = process.env.SUPABASE_SERVICE_KEY

export const dbMode: "supabase" | "local" =
  isConfigured(supabaseUrl) && isConfigured(supabaseKey) ? "supabase" : "local"

// ----------------------------------------------------------------------------
// Local emulator
// ----------------------------------------------------------------------------

const TABLES = ["evidence", "audit_log", "users", "cases", "case_access", "recovery_requests", "webhook_outbox"] as const

function dataDir(): string {
  const dir = process.env.DATA_DIR || path.join(process.cwd(), "data")
  fs.mkdirSync(dir, { recursive: true })
  return dir
}

function dbPath(): string {
  return path.join(dataDir(), "db.json")
}

function emptyDb(): Record<string, any[]> {
  return Object.fromEntries(TABLES.map(t => [t, []]))
}

export function resetLocalDb(): void {
  fs.writeFileSync(dbPath(), JSON.stringify(emptyDb(), null, 2), "utf-8")
}

function readDb(): Record<string, any[]> {
  const p = dbPath()
  if (!fs.existsSync(p)) {
    resetLocalDb()
    return emptyDb()
  }
  const parsed = JSON.parse(fs.readFileSync(p, "utf-8"))
  for (const t of TABLES) if (!Array.isArray(parsed[t])) parsed[t] = []
  return parsed
}

function writeDb(data: Record<string, any[]>) {
  const p = dbPath()
  fs.writeFileSync(`${p}.tmp`, JSON.stringify(data, null, 2), "utf-8")
  fs.renameSync(`${p}.tmp`, p)
}

type Op = "select" | "insert" | "update" | "upsert" | "delete"

class LocalQueryBuilder {
  private filters: Array<(row: any) => boolean> = []
  private orderCol?: string
  private orderAsc = true
  private limitN?: number
  private op: Op = "select"
  private payload?: any
  private conflictKey = "id"
  private result?: { data: any; error: any }

  constructor(private table: string) {}

  select(_cols?: string) { return this }
  eq(column: string, value: any) { this.filters.push(r => r[column] === value); return this }
  is(column: string, value: null | boolean) { this.filters.push(r => (r[column] ?? null) === value); return this }
  in(column: string, values: any[]) { this.filters.push(r => values.includes(r[column])); return this }
  order(column: string, options?: { ascending?: boolean }) { this.orderCol = column; this.orderAsc = options?.ascending !== false; return this }
  limit(n: number) { this.limitN = n; return this }
  insert(data: any | any[]) { this.op = "insert"; this.payload = Array.isArray(data) ? data : [data]; return this }
  update(values: any) { this.op = "update"; this.payload = values; return this }
  delete() { this.op = "delete"; return this }
  upsert(data: any | any[], options?: { onConflict?: string }) {
    this.op = "upsert"
    this.payload = Array.isArray(data) ? data : [data]
    if (options?.onConflict) this.conflictKey = options.onConflict
    return this
  }

  private matches(row: any) { return this.filters.every(fn => fn(row)) }

  private execute() {
    if (this.result) return this.result
    const db = readDb()
    const rows: any[] = db[this.table] || (db[this.table] = [])

    if (this.op === "insert") {
      for (const item of this.payload) {
        if (rows.some(r => r.id !== undefined && r.id === item.id)) {
          return (this.result = { data: null, error: { message: `duplicate key value violates unique constraint "${this.table}_pkey"`, code: "23505" } })
        }
      }
      rows.push(...this.payload)
      writeDb(db)
      return (this.result = { data: this.payload, error: null })
    }

    if (this.op === "upsert") {
      const key = this.conflictKey
      for (const item of this.payload) {
        const idx = rows.findIndex(r => r[key] === item[key])
        if (idx >= 0) rows[idx] = { ...rows[idx], ...item }
        else rows.push(item)
      }
      writeDb(db)
      return (this.result = { data: this.payload, error: null })
    }

    if (this.op === "update") {
      const updated: any[] = []
      db[this.table] = rows.map(r => {
        if (!this.matches(r)) return r
        const u = { ...r, ...this.payload }
        updated.push(u)
        return u
      })
      writeDb(db)
      return (this.result = { data: updated, error: null })
    }

    if (this.op === "delete") {
      const removed = rows.filter(r => this.matches(r))
      db[this.table] = rows.filter(r => !this.matches(r))
      writeDb(db)
      return (this.result = { data: removed, error: null })
    }

    let out = rows.filter(r => this.matches(r))
    if (this.orderCol) {
      const col = this.orderCol
      const dir = this.orderAsc ? 1 : -1
      out = [...out].sort((a, b) => (a[col] < b[col] ? -dir : a[col] > b[col] ? dir : 0))
    }
    if (this.limitN !== undefined) out = out.slice(0, this.limitN)
    return (this.result = { data: out, error: null })
  }

  async single() {
    const res = this.execute()
    if (res.error) return res
    const arr = res.data as any[]
    if (!arr || arr.length !== 1) {
      return { data: null, error: { message: arr && arr.length > 1 ? "Multiple rows returned" : "Row not found", code: "PGRST116" } }
    }
    return { data: arr[0], error: null }
  }

  async maybeSingle() {
    const res = this.execute()
    if (res.error) return res
    const arr = res.data as any[]
    return { data: arr && arr.length ? arr[0] : null, error: null }
  }

  then<T1 = any, T2 = never>(
    onfulfilled?: ((value: { data: any; error: any }) => T1 | PromiseLike<T1>) | null,
    onrejected?: ((reason: any) => T2 | PromiseLike<T2>) | null
  ): Promise<T1 | T2> {
    try {
      return Promise.resolve(this.execute()).then(onfulfilled, onrejected)
    } catch (err) {
      return Promise.reject(err).then(onfulfilled, onrejected)
    }
  }
}

function safeJoin(base: string, rel: string): string {
  const full = path.resolve(base, rel)
  if (!full.startsWith(path.resolve(base) + path.sep)) throw new Error("Invalid storage path")
  return full
}

class LocalStorageBucket {
  constructor(private bucket: string) {}

  private dir(): string {
    const root = process.env.STORAGE_DIR || path.join(process.cwd(), "storage")
    const d = path.join(root, this.bucket)
    fs.mkdirSync(d, { recursive: true })
    return d
  }

  async upload(storagePath: string, buffer: Buffer, options?: { upsert?: boolean }) {
    try {
      const full = safeJoin(this.dir(), storagePath)
      if (fs.existsSync(full) && !options?.upsert) return { data: null, error: { message: "The resource already exists" } }
      fs.mkdirSync(path.dirname(full), { recursive: true })
      fs.writeFileSync(full, buffer)
      return { data: { path: storagePath }, error: null }
    } catch (err: any) {
      return { data: null, error: { message: err.message || "Failed to write file to local storage" } }
    }
  }

  async download(storagePath: string) {
    try {
      const full = safeJoin(this.dir(), storagePath)
      if (!fs.existsSync(full)) return { data: null, error: { message: "Object not found" } }
      const buf = fs.readFileSync(full)
      // Mirror supabase-js, which returns a Blob.
      return { data: new Blob([buf]), error: null }
    } catch (err: any) {
      return { data: null, error: { message: err.message } }
    }
  }

  async remove(paths: string[]) {
    try {
      for (const p of paths) {
        const full = safeJoin(this.dir(), p)
        if (fs.existsSync(full)) fs.unlinkSync(full)
      }
      return { data: paths.map(name => ({ name })), error: null }
    } catch (err: any) {
      return { data: null, error: { message: err.message } }
    }
  }

  async list(prefix = "") {
    const base = this.dir()
    const out: Array<{ name: string }> = []
    const walk = (d: string) => {
      for (const e of fs.readdirSync(d, { withFileTypes: true })) {
        const full = path.join(d, e.name)
        if (e.isDirectory()) walk(full)
        else out.push({ name: path.relative(base, full) })
      }
    }
    const start = prefix ? safeJoin(base, prefix) : base
    if (fs.existsSync(start)) walk(start)
    return { data: out, error: null }
  }
}

function createLocalClient(): any {
  return {
    from: (table: string) => new LocalQueryBuilder(table),
    storage: { from: (bucket: string) => new LocalStorageBucket(bucket) }
  }
}

export const supabase: any =
  dbMode === "supabase"
    ? createClient(supabaseUrl!, supabaseKey!, { auth: { persistSession: false, autoRefreshToken: false } })
    : createLocalClient()

/** Reads a storage download result (Blob in supabase-js, Buffer-compatible locally) into a Buffer. */
export async function blobToBuffer(data: any): Promise<Buffer> {
  if (!data) return Buffer.alloc(0)
  if (Buffer.isBuffer(data)) return data
  if (typeof data.arrayBuffer === "function") return Buffer.from(await data.arrayBuffer())
  return Buffer.from(data)
}

/**
 * Startup check: confirms the tables from supabase/schema.sql and the storage bucket exist,
 * and returns human-readable problems instead of failing on the first request.
 */
export async function checkDatabaseConnection(): Promise<{ mode: string; ok: boolean; problems: string[] }> {
  const problems: string[] = []
  if (dbMode === "local") return { mode: "local", ok: true, problems }
  for (const table of TABLES) {
    const { error } = await supabase.from(table).select("*").limit(1)
    if (error) problems.push(`table "${table}": ${error.message}. Run supabase/schema.sql in the Supabase SQL editor.`)
  }
  const { error: bucketError } = await supabase.storage.from(EVIDENCE_BUCKET).list("", { limit: 1 })
  if (bucketError) problems.push(`storage bucket "${EVIDENCE_BUCKET}": ${bucketError.message}`)
  return { mode: "supabase", ok: problems.length === 0, problems }
}
