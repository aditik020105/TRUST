"use client"

import { useCallback, useEffect, useRef, useState } from "react"
import { useAuth } from "@/context/AuthContext"
import { CheckCircle, XCircle, Upload, RefreshCw } from "lucide-react"

const card: React.CSSProperties = { background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "1rem", marginBottom: "1rem", color: "#111827" }
const btn: React.CSSProperties = { padding: "0.4rem 0.8rem", borderRadius: 6, border: 0, background: "#16a34a", color: "#fff", fontWeight: 600, fontSize: "0.78rem", display: "inline-flex", alignItems: "center", gap: 5, cursor: "pointer" }
const danger: React.CSSProperties = { ...btn, background: "#dc2626" }
const muted: React.CSSProperties = { fontSize: "0.8rem", color: "#6b7280" }

interface Recovery {
  id: string
  email: string
  old_did: string
  new_did: string
  reason: string
  status: string
  approvals: Array<{ did: string; at: string }>
  required_approvals: number
  reduced_quorum: boolean
  created_at: string
  expires_at: string
}

/** Lost-key recovery requests: each needs approvals from distinct administrators. */
export function RecoveryPanel() {
  const { authFetch, did } = useAuth()
  const [rows, setRows] = useState<Recovery[]>([])
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)

  const load = useCallback(async () => {
    const res = await authFetch("/api/admin/recovery")
    if (res.ok) setRows((await res.json()).data)
  }, [authFetch])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load()
  }, [load])

  const act = async (id: string, action: "approve" | "reject") => {
    const res = await authFetch(`/api/admin/recovery/${id}/${action}`, { method: "POST" })
    const json = await res.json().catch(() => ({}))
    setMsg({ text: json.message || json.error || (res.ok ? "Done" : "Failed"), ok: res.ok })
    load()
  }

  return (
    <div style={card}>
      <h2 style={{ fontSize: "1.05rem", fontWeight: 700, margin: 0 }}>Lost-key recovery requests</h2>
      <p style={muted}>
        Confirm the person&apos;s identity out of band (in person or by a known phone number) before approving. Each request needs
        approvals from different administrators; nobody can approve their own account. On quorum the DID rotates to the new key,
        the old DID is retired but stays resolvable, and old sessions stop working.
      </p>
      {msg && <p style={{ fontSize: "0.82rem", color: msg.ok ? "#166534" : "#991b1b" }}>{msg.text}</p>}
      {rows.length === 0 ? <p style={muted}>No requests.</p> : (
        <table style={{ width: "100%", fontSize: "0.78rem", borderCollapse: "collapse" }}>
          <thead><tr style={{ textAlign: "left", color: "#6b7280" }}><th>Account</th><th>Reason</th><th>Approvals</th><th>Status</th><th /></tr></thead>
          <tbody>
            {rows.map(r => {
              const mine = r.approvals.some(a => a.did === did)
              return (
                <tr key={r.id} style={{ borderTop: "1px solid #f1f5f9", verticalAlign: "top" }}>
                  <td style={{ padding: "6px 0" }}>
                    <div style={{ fontWeight: 600 }}>{r.email}</div>
                    <div style={{ fontFamily: "monospace", fontSize: "0.68rem", color: "#6b7280" }}>{r.old_did} → {r.new_did}</div>
                    <div style={{ fontSize: "0.68rem", color: "#6b7280" }}>filed {new Date(r.created_at).toLocaleString()}, expires {new Date(r.expires_at).toLocaleString()}</div>
                  </td>
                  <td>{r.reason}</td>
                  <td>{r.approvals.length} / {r.required_approvals}{r.reduced_quorum ? " (reduced)" : ""}</td>
                  <td style={{ fontWeight: 700 }}>{r.status}</td>
                  <td style={{ textAlign: "right", whiteSpace: "nowrap" }}>
                    {r.status === "pending" && (
                      <>
                        <button type="button" style={btn} disabled={mine} onClick={() => act(r.id, "approve")} title={mine ? "You already approved" : "Approve"}>
                          <CheckCircle size={12} /> {mine ? "Approved" : "Approve"}
                        </button>{" "}
                        <button type="button" style={danger} onClick={() => act(r.id, "reject")}><XCircle size={12} /> Reject</button>
                      </>
                    )}
                  </td>
                </tr>
              )
            })}
          </tbody>
        </table>
      )}
    </div>
  )
}

/** Legacy logbook import and case-management connector status. */
export function DataPanel() {
  const { authFetch } = useAuth()
  const file = useRef<HTMLInputElement>(null)
  const [result, setResult] = useState<{ ok: boolean; text: string; errors?: string[] } | null>(null)
  const [connector, setConnector] = useState<{ configured: boolean; url: string | null; queued: number; delivered: number; failing: Array<{ eventId: string; attempts: number; lastError: string }> } | null>(null)

  const loadConnector = useCallback(async () => {
    const res = await authFetch("/api/admin/connector")
    if (res.ok) setConnector((await res.json()).data)
  }, [authFetch])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    loadConnector()
  }, [loadConnector])

  const runImport = async (dryRun: boolean) => {
    const f = file.current?.files?.[0]
    if (!f) return setResult({ ok: false, text: "Choose a CSV file first" })
    const fd = new FormData()
    fd.append("file", f)
    fd.append("dryRun", String(dryRun))
    const res = await authFetch("/api/admin/legacy-import", { method: "POST", body: fd })
    const json = await res.json().catch(() => ({}))
    const d = json.data || {}
    setResult(res.ok
      ? { ok: true, text: dryRun ? `Valid: ready to import (file SHA-256 ${String(d.fileSha256).slice(0, 16)}…)` : `Imported ${d.imported} entries; batch recorded in tx ${String(d.batchTx).slice(0, 16)}…` }
      : { ok: false, text: json.error || "Import rejected", errors: d.errors })
  }

  return (
    <>
      <div style={card}>
        <h2 style={{ fontSize: "1.05rem", fontWeight: 700, margin: 0 }}>Import legacy custody logbook</h2>
        <p style={muted}>
          CSV columns: <code>date, case_id, item, action, officer, notes</code>. Each row becomes a ledger event attested by you
          (marked as not signed by the original officer); the file&apos;s SHA-256 is anchored so the import can be matched to the scanned logbook.
        </p>
        <input ref={file} type="file" accept=".csv,text/csv" style={{ fontSize: "0.8rem" }} />{" "}
        <button type="button" style={{ ...btn, background: "#2563eb" }} onClick={() => runImport(true)}>Validate</button>{" "}
        <button type="button" style={btn} onClick={() => runImport(false)}><Upload size={12} /> Import</button>
        {result && (
          <div style={{ marginTop: 8, fontSize: "0.8rem", color: result.ok ? "#166534" : "#991b1b" }}>
            {result.text}
            {result.errors && <ul style={{ margin: "4px 0 0 1rem" }}>{result.errors.slice(0, 10).map(e => <li key={e}>{e}</li>)}</ul>}
          </div>
        )}
      </div>

      <div style={card}>
        <h2 style={{ fontSize: "1.05rem", fontWeight: 700, margin: 0, display: "flex", justifyContent: "space-between" }}>
          Case-management connector
          <button type="button" style={{ ...btn, background: "#475569" }} onClick={loadConnector}><RefreshCw size={12} /> Refresh</button>
        </h2>
        {!connector ? <p style={muted}>Loading...</p> : !connector.configured ? (
          <p style={muted}>Not configured. Set <code>CASE_MGMT_WEBHOOK_URL</code> and <code>CASE_MGMT_WEBHOOK_SECRET</code> on the backend to push every custody event (HMAC-signed, retried) to your case-management system. External systems can also pull <code>GET /api/cases/:caseId/custody</code>.</p>
        ) : (
          <div style={{ fontSize: "0.82rem" }}>
            <p>Delivering to <code>{connector.url}</code>: {connector.delivered} delivered, {connector.queued} queued.</p>
            {connector.failing.length > 0 && (
              <ul style={{ color: "#991b1b" }}>{connector.failing.map(f => <li key={f.eventId}>{f.eventId}: {f.attempts} attempts, {f.lastError}</li>)}</ul>
            )}
          </div>
        )}
      </div>
    </>
  )
}
