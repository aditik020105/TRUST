import crypto from "crypto"
import { supabase } from "../lib/supabase"

/**
 * Single place where custody events are mirrored into the audit_log table (after the ledger
 * commit), and queued for the case-management connector.
 *
 * Connector: when CASE_MGMT_WEBHOOK_URL is set, every event is POSTed as JSON to that URL with
 *   X-Trust-Event-Id:  the audit log id (use it to de-duplicate retries)
 *   X-Trust-Signature: sha256=<hex HMAC-SHA256 of the raw body with CASE_MGMT_WEBHOOK_SECRET>
 * Deliveries go through the webhook_outbox table and are retried with exponential backoff, so
 * an outage of the external system never blocks or loses custody events.
 */

export interface AuditRowInput {
  id: string
  evidence_id: string
  case_id: string
  action: string
  performed_by: string
  tx_hash: string
  block_number?: number | null
  details?: string | null
  timestamp?: string
}

export function webhookConfigured(): boolean {
  return !!process.env.CASE_MGMT_WEBHOOK_URL
}

export async function insertAuditRow(row: AuditRowInput): Promise<void> {
  const full = { ...row, timestamp: row.timestamp || new Date().toISOString(), details: row.details ?? null, block_number: row.block_number ?? null }
  const { error } = await supabase.from("audit_log").insert(full)
  if (error) {
    // The ledger already holds the event; reconciliation will flag the missing DB row.
    console.error(`[audit] ledger tx ${row.tx_hash} committed but audit_log insert failed: ${error.message}`)
    return
  }
  if (webhookConfigured()) {
    const { error: qErr } = await supabase.from("webhook_outbox").insert({
      id: `WH-${row.id}`,
      event_id: row.id,
      payload: JSON.stringify({ type: "custody_event", event: { ...full, evidenceId: full.evidence_id, caseId: full.case_id, performedBy: full.performed_by, txHash: full.tx_hash } }),
      attempts: 0,
      next_attempt_at: new Date().toISOString(),
      delivered_at: null,
      last_error: null,
      created_at: new Date().toISOString()
    })
    if (qErr) console.error(`[connector] could not queue event ${row.id}: ${qErr.message}`)
  }
}

export function signWebhookBody(body: string, secret: string): string {
  return "sha256=" + crypto.createHmac("sha256", secret).update(body).digest("hex")
}

/** Delivers due outbox entries once. Returns counts. Called by a timer and by tests. */
export async function deliverOutbox(limit = 50): Promise<{ delivered: number; failed: number }> {
  const url = process.env.CASE_MGMT_WEBHOOK_URL
  if (!url) return { delivered: 0, failed: 0 }
  const secret = process.env.CASE_MGMT_WEBHOOK_SECRET || ""
  const { data } = await supabase.from("webhook_outbox").select("*").is("delivered_at", null).order("created_at", { ascending: true }).limit(500)
  const due = (data || []).filter((r: any) => new Date(r.next_attempt_at).getTime() <= Date.now()).slice(0, limit)
  let delivered = 0
  let failed = 0
  for (const item of due) {
    try {
      const res = await fetch(url, {
        method: "POST",
        headers: { "Content-Type": "application/json", "X-Trust-Event-Id": item.event_id, "X-Trust-Signature": signWebhookBody(item.payload, secret) },
        body: item.payload,
        signal: AbortSignal.timeout(5000)
      })
      if (!res.ok) throw new Error(`HTTP ${res.status}`)
      await supabase.from("webhook_outbox").update({ delivered_at: new Date().toISOString(), attempts: item.attempts + 1, last_error: null }).eq("id", item.id)
      delivered++
    } catch (err: any) {
      const attempts = item.attempts + 1
      const backoffMs = Math.min(60 * 60 * 1000, 2 ** attempts * 5000)
      await supabase.from("webhook_outbox").update({
        attempts, last_error: String(err?.message || err).slice(0, 300), next_attempt_at: new Date(Date.now() + backoffMs).toISOString()
      }).eq("id", item.id)
      failed++
    }
  }
  return { delivered, failed }
}

export async function outboxStatus() {
  const { data } = await supabase.from("webhook_outbox").select("*")
  const rows = data || []
  return {
    configured: webhookConfigured(),
    url: process.env.CASE_MGMT_WEBHOOK_URL ? new URL(process.env.CASE_MGMT_WEBHOOK_URL).origin : null,
    queued: rows.filter((r: any) => !r.delivered_at).length,
    delivered: rows.filter((r: any) => r.delivered_at).length,
    failing: rows.filter((r: any) => !r.delivered_at && r.attempts > 0).map((r: any) => ({ eventId: r.event_id, attempts: r.attempts, lastError: r.last_error })).slice(0, 20)
  }
}

let timer: NodeJS.Timeout | null = null
export function startOutboxWorker(): void {
  if (!webhookConfigured() || timer) return
  timer = setInterval(() => {
    deliverOutbox().catch(err => console.error("[connector] delivery run failed:", err))
  }, Number(process.env.CASE_MGMT_WEBHOOK_INTERVAL_MS || 5000))
  timer.unref?.()
  console.log(`[connector] delivering custody events to ${new URL(process.env.CASE_MGMT_WEBHOOK_URL!).origin}`)
}
