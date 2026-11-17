import fs from "fs"
import path from "path"
import crypto from "crypto"
import { supabase, dbMode, EVIDENCE_BUCKET, blobToBuffer } from "../lib/supabase"
import { runReconciliation, ReconciliationReport } from "./reconciliation.service"

/**
 * Off-chain backup and restore. The ledger is never restored from a backup: it is the
 * reference the restored database is checked against.
 */

export const BACKUP_TABLES: Array<{ name: string; key: string }> = [
  { name: "users", key: "uid" },
  { name: "cases", key: "case_id" },
  { name: "case_access", key: "id" },
  { name: "recovery_requests", key: "id" },
  { name: "evidence", key: "id" },
  { name: "audit_log", key: "id" }
]

const sha = (b: Buffer) => crypto.createHash("sha256").update(b).digest("hex")

async function fetchAll(table: string, key: string): Promise<any[]> {
  const rows: any[] = []
  for (let from = 0; ; from += 1000) {
    const q: any = supabase.from(table).select("*").order(key, { ascending: true })
    const { data, error } = typeof q.range === "function" ? await q.range(from, from + 999) : await q
    if (error) throw new Error(`${table}: ${error.message}`)
    rows.push(...(data || []))
    if (!data || data.length < 1000 || typeof q.range !== "function") break
  }
  return rows
}

export async function createBackup(dir: string): Promise<{ dir: string; counts: Record<string, number>; blobs: number }> {
  fs.mkdirSync(path.join(dir, "blobs"), { recursive: true })
  const manifest: Array<{ file: string; sha256: string; bytes: number }> = []
  const write = (rel: string, buf: Buffer) => {
    const full = path.join(dir, rel)
    fs.mkdirSync(path.dirname(full), { recursive: true })
    fs.writeFileSync(full, buf)
    manifest.push({ file: rel, sha256: sha(buf), bytes: buf.length })
  }
  const counts: Record<string, number> = {}
  let evidenceRows: any[] = []
  for (const t of BACKUP_TABLES) {
    const rows = await fetchAll(t.name, t.key)
    counts[t.name] = rows.length
    if (t.name === "evidence") evidenceRows = rows
    write(`${t.name}.json`, Buffer.from(JSON.stringify(rows, null, 2)))
  }
  let blobs = 0
  for (const e of evidenceRows) {
    if (!e.file_url) continue
    const { data, error } = await supabase.storage.from(EVIDENCE_BUCKET).download(e.file_url)
    if (error || !data) {
      console.warn(`[backup] blob for ${e.id} missing: ${error?.message}`)
      continue
    }
    write(path.join("blobs", e.file_url), await blobToBuffer(data))
    blobs++
  }
  fs.writeFileSync(path.join(dir, "manifest.json"), JSON.stringify({ format: "trust-backup/2", createdAt: new Date().toISOString(), database: dbMode, files: manifest }, null, 2))
  return { dir, counts, blobs }
}

export async function restoreBackup(dir: string, opts: { force?: boolean } = {}): Promise<{ restored: Record<string, number>; blobs: number; reconciliation: ReconciliationReport }> {
  const manifest = JSON.parse(fs.readFileSync(path.join(dir, "manifest.json"), "utf-8"))
  for (const f of manifest.files) {
    const buf = fs.readFileSync(path.join(dir, f.file))
    if (sha(buf) !== f.sha256) throw new Error(`Backup file ${f.file} does not match its manifest hash: refusing to restore`)
  }
  if (!opts.force) {
    for (const t of BACKUP_TABLES) {
      const { data } = await supabase.from(t.name).select(t.key).limit(1)
      if (data && data.length) throw new Error(`Target table ${t.name} is not empty; restore into an empty database or pass force`)
    }
  }
  const restored: Record<string, number> = {}
  for (const t of BACKUP_TABLES) {
    const file = path.join(dir, `${t.name}.json`)
    if (!fs.existsSync(file)) continue
    const rows: any[] = JSON.parse(fs.readFileSync(file, "utf-8"))
    for (let i = 0; i < rows.length; i += 500) {
      const chunk = rows.slice(i, i + 500)
      // audit_log is append-only: insert; everything else upsert
      const { error } = t.name === "audit_log"
        ? await supabase.from(t.name).insert(chunk)
        : await supabase.from(t.name).upsert(chunk, { onConflict: t.key })
      if (error && !(t.name === "audit_log" && /duplicate/i.test(error.message))) throw new Error(`${t.name}: ${error.message}`)
    }
    restored[t.name] = rows.length
  }
  let blobs = 0
  for (const f of manifest.files.filter((x: any) => x.file.startsWith("blobs" + path.sep) || x.file.startsWith("blobs/"))) {
    const rel = f.file.replace(/^blobs[\\/]/, "")
    const { error } = await supabase.storage.from(EVIDENCE_BUCKET).upload(rel, fs.readFileSync(path.join(dir, f.file)), { upsert: true, contentType: "application/octet-stream" })
    if (error) throw new Error(`blob ${rel}: ${error.message}`)
    blobs++
  }
  // A restored database must be checked against the ledger before anyone relies on it.
  const reconciliation = await runReconciliation()
  return { restored, blobs, reconciliation }
}
