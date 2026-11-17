import cron from "node-cron"
import { supabase } from "../lib/supabase"
import { hyperledgerService } from "./hyperledger.service"
import { caseAccessService } from "./case-access.service"

/**
 * Compares the database (fast index) with the ledger (source of truth) and reports any event
 * that exists in one store but not the other, or whose fields disagree. A restored or edited
 * database shows up here before anyone relies on it.
 */

export interface ReconciliationIssue {
  kind:
    | "audit_missing_on_ledger"
    | "audit_missing_in_db"
    | "audit_mismatch"
    | "evidence_missing_on_ledger"
    | "evidence_missing_in_db"
    | "evidence_mismatch"
    | "chain_broken"
  id: string
  detail: string
}

export interface ReconciliationReport {
  ranAt: string
  ok: boolean
  durationMs: number
  counts: { dbAudit: number; ledgerAudit: number; dbEvidence: number; ledgerEvidence: number }
  issues: ReconciliationIssue[]
  error?: string
}

let lastReport: ReconciliationReport | null = null

export function getLastReconciliation(): ReconciliationReport | null {
  return lastReport
}

async function fetchAll(table: string): Promise<any[]> {
  // Supabase caps a select at 1000 rows by default; page through.
  const pageSize = 1000
  const out: any[] = []
  for (let from = 0; ; from += pageSize) {
    const q: any = supabase.from(table).select("*").order("id", { ascending: true })
    const { data, error } = typeof q.range === "function" ? await q.range(from, from + pageSize - 1) : await q
    if (error) throw new Error(`${table}: ${error.message}`)
    out.push(...(data || []))
    if (!data || data.length < pageSize || typeof q.range !== "function") break
  }
  return out
}

export async function runReconciliation(): Promise<ReconciliationReport> {
  const started = Date.now()
  const issues: ReconciliationIssue[] = []
  try {
    const [dbAudit, dbEvidence, ledgerAudit, ledgerEvidence, chain] = await Promise.all([
      fetchAll("audit_log"),
      fetchAll("evidence"),
      hyperledgerService.listAudit(),
      hyperledgerService.listEvidence(),
      hyperledgerService.verifyChain()
    ])

    const ledgerAuditById = new Map(ledgerAudit.map(a => [a.logId, a]))
    const dbAuditIds = new Set<string>()
    for (const r of dbAudit) {
      dbAuditIds.add(r.id)
      const l = ledgerAuditById.get(r.id)
      if (!l) {
        issues.push({ kind: "audit_missing_on_ledger", id: r.id, detail: `DB row (${r.action} by ${r.performed_by}, tx ${r.tx_hash}) has no ledger record` })
        continue
      }
      const diffs: string[] = []
      if (l.txId !== r.tx_hash) diffs.push(`tx db=${r.tx_hash} ledger=${l.txId}`)
      if (l.action !== r.action) diffs.push(`action db=${r.action} ledger=${l.action}`)
      if (l.performedByDid !== r.performed_by) diffs.push(`performer db=${r.performed_by} ledger=${l.performedByDid}`)
      if (l.targetId !== r.evidence_id) diffs.push(`target db=${r.evidence_id} ledger=${l.targetId}`)
      if (diffs.length) issues.push({ kind: "audit_mismatch", id: r.id, detail: diffs.join("; ") })
    }
    for (const l of ledgerAudit) {
      if (!dbAuditIds.has(l.logId)) {
        issues.push({ kind: "audit_missing_in_db", id: l.logId, detail: `ledger event ${l.action} on ${l.targetId} (tx ${l.txId}) has no DB row` })
      }
    }

    const ledgerEvById = new Map(ledgerEvidence.map(e => [e.id, e]))
    const dbEvIds = new Set<string>()
    for (const r of dbEvidence) {
      dbEvIds.add(r.id)
      const l = ledgerEvById.get(r.id)
      if (!l) {
        issues.push({ kind: "evidence_missing_on_ledger", id: r.id, detail: `evidence row ${r.name} is not anchored on the ledger` })
        continue
      }
      const diffs: string[] = []
      if (l.fileHash !== r.hash) diffs.push("hash")
      if (l.status !== r.status) diffs.push(`status db=${r.status} ledger=${l.status}`)
      if (l.caseId !== r.case_id) diffs.push("case ID")
      if (l.uploadedByDid !== r.uploaded_by) diffs.push("uploader")
      if (diffs.length) issues.push({ kind: "evidence_mismatch", id: r.id, detail: diffs.join("; ") })
    }
    for (const l of ledgerEvidence) {
      if (!dbEvIds.has(l.id)) issues.push({ kind: "evidence_missing_in_db", id: l.id, detail: `ledger evidence (case ${l.caseId}) has no DB row` })
    }

    if (chain && !chain.ok) issues.push({ kind: "chain_broken", id: `block-${chain.firstBadBlock ?? "?"}`, detail: chain.reason || "hash chain broken" })

    lastReport = {
      ranAt: new Date().toISOString(),
      ok: issues.length === 0,
      durationMs: Date.now() - started,
      counts: { dbAudit: dbAudit.length, ledgerAudit: ledgerAudit.length, dbEvidence: dbEvidence.length, ledgerEvidence: ledgerEvidence.length },
      issues
    }
  } catch (err: any) {
    lastReport = {
      ranAt: new Date().toISOString(),
      ok: false,
      durationMs: Date.now() - started,
      counts: { dbAudit: 0, ledgerAudit: 0, dbEvidence: 0, ledgerEvidence: 0 },
      issues,
      error: err?.message || String(err)
    }
  }
  if (!lastReport.ok) {
    console.warn(`[reconcile] ${lastReport.issues.length} issue(s)${lastReport.error ? `, error: ${lastReport.error}` : ""}`)
  }
  return lastReport
}

export function startReconciliationJob(): void {
  const schedule = process.env.RECONCILE_CRON || "*/10 * * * *"
  if (schedule === "off") return
  cron.schedule(schedule, () => {
    runReconciliation().catch(err => console.error("[reconcile] failed:", err))
  })
  console.log(`[reconcile] DB-vs-ledger reconciliation scheduled (${schedule})`)
  // Delegations that ran out get an "access_expired" ledger event within a minute.
  cron.schedule("* * * * *", () => {
    caseAccessService.recordExpiries().catch(err => console.error("[delegation] expiry sweep failed:", err))
  })
}
