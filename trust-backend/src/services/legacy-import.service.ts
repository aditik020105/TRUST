import crypto from "crypto"
import { v4 as uuidv4 } from "uuid"
import { hyperledgerService } from "./hyperledger.service"
import { insertAuditRow } from "./audit-row.service"

/**
 * Imports entries from paper / spreadsheet custody logbooks kept before TRUST.
 *
 * Expected CSV header (case-insensitive): date, case_id, item, action, officer[, notes]
 * Each row becomes a ledger event "legacy_<action>" on target LEGACY-<case_id>, attested by the
 * importing administrator. The original officer did NOT sign these entries; the record says so
 * explicitly, and the whole file's SHA-256 is anchored in a "legacy_import_batch" event so the
 * import can be matched to the scanned source document.
 */

export interface LegacyRow { date: string; case_id: string; item: string; action: string; officer: string; notes: string }

/** Minimal RFC 4180 CSV parser (quoted fields, escaped quotes, CRLF). */
export function parseCsv(text: string): string[][] {
  const rows: string[][] = []
  let row: string[] = []
  let field = ""
  let quoted = false
  for (let i = 0; i < text.length; i++) {
    const c = text[i]
    if (quoted) {
      if (c === '"' && text[i + 1] === '"') { field += '"'; i++ }
      else if (c === '"') quoted = false
      else field += c
    } else if (c === '"') quoted = true
    else if (c === ",") { row.push(field); field = "" }
    else if (c === "\n" || c === "\r") {
      if (c === "\r" && text[i + 1] === "\n") i++
      row.push(field); field = ""
      if (row.some(f => f.trim() !== "")) rows.push(row)
      row = []
    } else field += c
  }
  row.push(field)
  if (row.some(f => f.trim() !== "")) rows.push(row)
  return rows
}

const CASE_RE = /^[A-Za-z0-9][A-Za-z0-9_\-.]{0,63}$/

export function validateLegacyCsv(text: string): { rows: LegacyRow[]; errors: string[] } {
  const table = parseCsv(text.replace(/^﻿/, ""))
  if (!table.length) return { rows: [], errors: ["File is empty"] }
  const header = table[0].map(h => h.trim().toLowerCase())
  const need = ["date", "case_id", "item", "action", "officer"]
  const missing = need.filter(n => !header.includes(n))
  if (missing.length) return { rows: [], errors: [`Missing column(s): ${missing.join(", ")}`] }
  const idx = (n: string) => header.indexOf(n)
  const rows: LegacyRow[] = []
  const errors: string[] = []
  table.slice(1).forEach((r, i) => {
    const line = i + 2
    const get = (n: string) => (idx(n) >= 0 ? (r[idx(n)] || "").trim() : "")
    const row = { date: get("date"), case_id: get("case_id"), item: get("item"), action: get("action"), officer: get("officer"), notes: get("notes") }
    if (!row.date || isNaN(Date.parse(row.date))) errors.push(`line ${line}: invalid date "${row.date}"`)
    else if (!CASE_RE.test(row.case_id)) errors.push(`line ${line}: invalid case_id "${row.case_id}"`)
    else if (!row.item || !row.action || !row.officer) errors.push(`line ${line}: item, action and officer are required`)
    else rows.push(row)
  })
  if (rows.length > 5000) errors.push("At most 5000 rows per import")
  return { rows, errors }
}

export async function importLegacyLog(
  text: string,
  fileName: string,
  admin: { did: string; mspId: string },
  dryRun: boolean
): Promise<{ imported: number; errors: string[]; fileSha256: string; batchTx?: string }> {
  const { rows, errors } = validateLegacyCsv(text)
  const fileSha256 = crypto.createHash("sha256").update(text).digest("hex")
  if (errors.length || dryRun) return { imported: 0, errors, fileSha256 }

  const batchId = `LEGACY-${uuidv4().slice(0, 8).toUpperCase()}`
  for (const [i, r] of rows.entries()) {
    const action = `legacy_${r.action.toLowerCase().replace(/[^a-z0-9]+/g, "_").replace(/^_|_$/g, "").slice(0, 40) || "entry"}`
    const details = JSON.stringify({
      batchId, row: i + 2, originalDate: new Date(r.date).toISOString(), item: r.item, officer: r.officer, notes: r.notes,
      attestation: "Transcribed from a pre-TRUST logbook and attested by the importing administrator; not signed by the original officer."
    })
    const logId = `LOG-${uuidv4().slice(0, 8).toUpperCase()}`
    const target = `LEGACY-${r.case_id}`
    const ledger = await hyperledgerService.recordAudit({ logId, targetId: target, caseId: r.case_id, action, performedByDid: admin.did, mspId: admin.mspId, details })
    await insertAuditRow({ id: logId, evidence_id: target, case_id: r.case_id, action, performed_by: admin.did, tx_hash: ledger.txId, block_number: ledger.blockNumber, details })
  }
  const logId = `LOG-${uuidv4().slice(0, 8).toUpperCase()}`
  const details = JSON.stringify({ batchId, fileName, fileSha256, rows: rows.length })
  const batch = await hyperledgerService.recordAudit({ logId, targetId: batchId, caseId: "LEGACY-IMPORT", action: "legacy_import_batch", performedByDid: admin.did, mspId: admin.mspId, details })
  await insertAuditRow({ id: logId, evidence_id: batchId, case_id: "LEGACY-IMPORT", action: "legacy_import_batch", performed_by: admin.did, tx_hash: batch.txId, block_number: batch.blockNumber, details })
  return { imported: rows.length, errors: [], fileSha256, batchTx: batch.txId }
}
