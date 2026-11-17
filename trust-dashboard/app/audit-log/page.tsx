"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { AuditEntry } from "@/types"
import AuditLogTable from "@/components/AuditLogTable"
import ProtectedRoute from "@/components/ProtectedRoute"
import { useAuth } from "@/context/AuthContext"
import { Lock, AlertOctagon } from "lucide-react"
import styles from "./page.module.css"

function AuditLogContent() {
  const [entries, setEntries] = useState<AuditEntry[]>([])
  const [loading, setLoading] = useState(true)
  const [serverRejection, setServerRejection] = useState<{
    httpStatus: number
    rule?: string
    reason: string
  } | null>(null)
  const { user, role, did, status: userStatus, authFetch } = useAuth()
  const [draft, setDraft] = useState({ evidenceId: "", caseId: "", performedBy: "", action: "" })
  const [filters, setFilters] = useState(draft)

  useEffect(() => {
    async function loadAuditLog() {
      setLoading(true)
      setServerRejection(null)
      try {
        const qs = new URLSearchParams(Object.entries(filters).filter(([, v]) => v.trim()) as [string, string][])
        const res = await authFetch(`/api/audit-log${qs.toString() ? `?${qs}` : ""}`)
        const json = await res.json().catch(() => ({}))
        if (!res.ok) {
          setEntries([])
          setServerRejection({
            httpStatus: res.status,
            rule: json.opaDecision?.rule,
            reason: json.error || json.message || "Server rejected audit log request"
          })
        } else if (Array.isArray(json.data)) {
          setEntries(json.data)
        }
      } catch (err) {
        console.error("Error fetching audit log:", err)
      } finally {
        setLoading(false)
      }
    }

    loadAuditLog()
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user?.uid, role, did, userStatus, filters])

  const filterBar = (
    <form
      onSubmit={e => { e.preventDefault(); setFilters(draft) }}
      style={{ display: "flex", flexWrap: "wrap", gap: "0.5rem", margin: "0 0 1rem", alignItems: "center" }}
    >
      {([
        ["evidenceId", "Evidence ID or DID"],
        ["caseId", "Case ID"],
        ["performedBy", "Performed by (DID)"]
      ] as const).map(([k, label]) => (
        <input key={k} placeholder={label} value={draft[k]} onChange={e => setDraft({ ...draft, [k]: e.target.value })}
          style={{ padding: "0.45rem 0.6rem", borderRadius: 6, border: "1px solid #cbd5e1", fontSize: "0.82rem", minWidth: 160, flex: "1 1 160px" }} />
      ))}
      <select value={draft.action} onChange={e => setDraft({ ...draft, action: e.target.value })}
        style={{ padding: "0.45rem 0.6rem", borderRadius: 6, border: "1px solid #cbd5e1", fontSize: "0.82rem" }}>
        <option value="">Any action</option>
        {["uploaded", "accessed", "viewed", "downloaded", "status_verified", "status_flagged", "status_pending", "integrity_checked",
          "user_approved", "user_revoked", "did_registered_pending"].map(a => <option key={a} value={a}>{a.replace(/_/g, " ")}</option>)}
      </select>
      <button type="submit" style={{ padding: "0.45rem 0.9rem", borderRadius: 6, border: 0, background: "#dc2626", color: "#fff", fontWeight: 600, fontSize: "0.82rem" }}>Filter</button>
      <button type="button" onClick={() => { const empty = { evidenceId: "", caseId: "", performedBy: "", action: "" }; setDraft(empty); setFilters(empty) }}
        style={{ padding: "0.45rem 0.9rem", borderRadius: 6, border: "1px solid #cbd5e1", background: "transparent", fontSize: "0.82rem" }}>Clear</button>
    </form>
  )

  if (loading) return <div>{filterBar}<p style={{ color: "#94a3b8", padding: "2rem" }}>Loading audit log...</p></div>

  return (
    <div>
      <div className={styles.topBar}>
        <div>
          <h1 className={styles.heading}>Audit Log</h1>
          <p className={styles.subheading}>
            {entries.length} custody events; each row is paired with a ledger transaction
          </p>
        </div>
        <div className={styles.badge}>
          <Lock size={13} />
          Immutable Ledger
        </div>
      </div>

      {filterBar}

      {serverRejection ? (
        <div
          style={{
            background: "#fef2f2",
            border: "2px solid #ef4444",
            borderRadius: "12px",
            padding: "1.5rem",
            marginBottom: "2rem",
            color: "#7f1d1d"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px", fontSize: "1.1rem", fontWeight: 700, color: "#b91c1c", marginBottom: "0.5rem" }}>
            <AlertOctagon size={22} />
            <span>
              HTTP {serverRejection.httpStatus} — Audit Log Access Rejected by Backend Server
            </span>
          </div>
          <p style={{ fontFamily: "monospace", fontSize: "0.9rem", background: "rgba(239,68,68,0.1)", padding: "0.85rem", borderRadius: "8px", margin: "0.5rem 0" }}>
            {serverRejection.reason}
          </p>
          {serverRejection.rule && (
            <div style={{ fontSize: "0.82rem", marginTop: "0.5rem" }}>
              <strong>OPA Policy Rule Triggered:</strong> <code>{serverRejection.rule}</code> |{" "}
              <strong>Evaluated DID:</strong> <code>{did}</code> |{" "}
              <strong>User Status:</strong> <code>{userStatus}</code>
            </div>
          )}
          <div style={{ marginTop: "1rem", fontSize: "0.82rem" }}>
            If your account is pending or revoked, ask an administrator to review it. <Link href="/dashboard" style={{ textDecoration: "underline" }}>Back to dashboard</Link>
          </div>
        </div>
      ) : (
        <AuditLogTable entries={entries} />
      )}
    </div>
  )
}

export default function AuditLog() {
  return (
    <ProtectedRoute>
      <AuditLogContent />
    </ProtectedRoute>
  )
}