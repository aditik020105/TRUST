"use client"

import { useCallback, useEffect, useState } from "react"
import ProtectedRoute from "@/components/ProtectedRoute"
import { useAuth } from "@/context/AuthContext"
import { FolderLock, UserPlus, Ban, Clock, Download } from "lucide-react"
import styles from "../audit-log/page.module.css"

interface Grant {
  id: string
  granteeDid: string
  permission: "read" | "contribute"
  grantedBy: string
  expiresAt: string
  revokedAt: string | null
  state: "active" | "revoked" | "expired"
  txHash: string
}

interface CaseItem {
  caseId: string
  ownerDid: string
  createdAt: string
  access: string
  grants: Grant[]
}

const field: React.CSSProperties = { padding: "0.45rem 0.6rem", borderRadius: 6, border: "1px solid #cbd5e1", fontSize: "0.82rem" }
const btn: React.CSSProperties = { padding: "0.45rem 0.8rem", borderRadius: 6, border: 0, background: "#dc2626", color: "#fff", fontWeight: 600, fontSize: "0.8rem", display: "inline-flex", alignItems: "center", gap: 6, cursor: "pointer" }
const ghost: React.CSSProperties = { ...btn, background: "transparent", color: "#991b1b", border: "1px solid #fecaca" }
const stateColor = { active: "#166534", revoked: "#991b1b", expired: "#6b7280" }

function GrantForm({ caseId, onDone }: { caseId: string; onDone: (msg: string, ok: boolean) => void }) {
  const { authFetch } = useAuth()
  const [grantee, setGrantee] = useState("")
  const [permission, setPermission] = useState<"read" | "contribute">("read")
  const [hours, setHours] = useState(72)
  const [busy, setBusy] = useState(false)

  const submit = async (e: React.FormEvent) => {
    e.preventDefault()
    setBusy(true)
    try {
      const body = grantee.startsWith("did:") ? { granteeDid: grantee.trim() } : { granteeEmail: grantee.trim() }
      const res = await authFetch(`/api/cases/${encodeURIComponent(caseId)}/access`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ ...body, permission, expiresInHours: hours })
      })
      const json = await res.json().catch(() => ({}))
      if (res.ok) {
        setGrantee("")
        onDone(`Granted ${permission} access until ${new Date(json.data.expiresAt).toLocaleString()} (ledger tx ${String(json.data.txHash).slice(0, 12)}…)`, true)
      } else onDone(json.error || "Delegation failed", false)
    } finally {
      setBusy(false)
    }
  }

  return (
    <form onSubmit={submit} style={{ display: "flex", flexWrap: "wrap", gap: 8, alignItems: "center", marginTop: 10 }}>
      <input required placeholder="Email or DID of the person" value={grantee} onChange={e => setGrantee(e.target.value)} style={{ ...field, flex: "1 1 220px" }} />
      <select value={permission} onChange={e => setPermission(e.target.value as "read" | "contribute")} style={field}>
        <option value="read">Read (in-browser view, verify)</option>
        <option value="contribute">Contribute (also add evidence)</option>
      </select>
      <label style={{ fontSize: "0.8rem", display: "flex", alignItems: "center", gap: 4 }}>
        for
        <input type="number" min={1} max={720} value={hours} onChange={e => setHours(Number(e.target.value))} style={{ ...field, width: 72 }} />
        hours
      </label>
      <button type="submit" style={btn} disabled={busy}><UserPlus size={14} /> Delegate</button>
    </form>
  )
}

function CasesContent() {
  const { authFetch, user } = useAuth()
  const [cases, setCases] = useState<CaseItem[]>([])
  const [mode, setMode] = useState<string>("")
  const [msg, setMsg] = useState<{ text: string; ok: boolean } | null>(null)
  const [loading, setLoading] = useState(true)

  const load = useCallback(async () => {
    const res = await authFetch("/api/cases")
    const json = await res.json().catch(() => ({}))
    if (res.ok) {
      setCases(json.data || [])
      setMode(json.mode)
    } else setMsg({ text: json.error || "Could not load cases", ok: false })
    setLoading(false)
  }, [authFetch])

  useEffect(() => {
    // eslint-disable-next-line react-hooks/set-state-in-effect
    load()
  }, [load])

  const revoke = async (caseId: string, grantId: string) => {
    const res = await authFetch(`/api/cases/${encodeURIComponent(caseId)}/access/${grantId}/revoke`, { method: "POST" })
    const json = await res.json().catch(() => ({}))
    setMsg(res.ok ? { text: `Delegation ${grantId} revoked`, ok: true } : { text: json.error || "Revoke failed", ok: false })
    load()
  }

  const exportCustody = async (caseId: string) => {
    const res = await authFetch(`/api/cases/${encodeURIComponent(caseId)}/custody`)
    if (!res.ok) return setMsg({ text: "Export failed", ok: false })
    const url = URL.createObjectURL(new Blob([JSON.stringify((await res.json()).data, null, 2)], { type: "application/json" }))
    const a = document.createElement("a")
    a.href = url
    a.download = `custody-${caseId}.json`
    a.click()
    URL.revokeObjectURL(url)
  }

  const canManage = (c: CaseItem) => c.ownerDid === user?.did || user?.role === "admin"

  return (
    <div>
      <div className={styles.topBar}>
        <div>
          <h1 className={styles.heading}>Cases &amp; Access</h1>
          <p className={styles.subheading}>
            {mode === "open"
              ? "Case scoping is off (CASE_ACCESS_MODE=open): every approved role sees every case."
              : "You see cases you opened or were delegated to. Judges, auditors and admins see all cases. Every grant, revocation and expiry is a ledger event."}
          </p>
        </div>
        <div className={styles.badge}><FolderLock size={13} /> Time-bound delegation</div>
      </div>

      {msg && (
        <div style={{ margin: "0 0 1rem", padding: "0.6rem 0.8rem", borderRadius: 8, fontSize: "0.85rem", background: msg.ok ? "#f0fdf4" : "#fef2f2", color: msg.ok ? "#166534" : "#991b1b", border: `1px solid ${msg.ok ? "#bbf7d0" : "#fecaca"}` }}>
          {msg.text}
        </div>
      )}

      {loading ? <p style={{ color: "#94a3b8" }}>Loading cases...</p> : cases.length === 0 ? (
        <p style={{ color: "#64748b" }}>No cases yet. A case is opened by its first evidence upload, and the uploader owns it.</p>
      ) : cases.map(c => (
        <div key={c.caseId} style={{ background: "#fff", border: "1px solid #e5e7eb", borderRadius: 10, padding: "1rem", marginBottom: "0.9rem" }}>
          <div style={{ display: "flex", justifyContent: "space-between", flexWrap: "wrap", gap: 8 }}>
            <div>
              <div style={{ fontWeight: 700, fontSize: "1rem" }}>{c.caseId}</div>
              <div style={{ fontSize: "0.75rem", color: "#6b7280", fontFamily: "monospace" }}>owner {c.ownerDid} · opened {new Date(c.createdAt).toLocaleString()}</div>
            </div>
            <div style={{ display: "flex", gap: 8, alignItems: "center" }}>
              <span style={{ fontSize: "0.72rem", fontWeight: 700, textTransform: "uppercase", background: "#f1f5f9", padding: "3px 8px", borderRadius: 6 }}>your access: {c.access}</span>
              <button type="button" style={ghost} onClick={() => exportCustody(c.caseId)}><Download size={13} /> Custody JSON</button>
            </div>
          </div>

          {c.grants.length > 0 && (
            <table style={{ width: "100%", marginTop: 10, fontSize: "0.78rem", borderCollapse: "collapse" }}>
              <thead>
                <tr style={{ textAlign: "left", color: "#6b7280" }}><th>Grantee</th><th>Permission</th><th>Expires</th><th>State</th><th /></tr>
              </thead>
              <tbody>
                {c.grants.map(g => (
                  <tr key={g.id} style={{ borderTop: "1px solid #f1f5f9" }}>
                    <td style={{ fontFamily: "monospace", padding: "4px 0" }}>{g.granteeDid}</td>
                    <td>{g.permission}</td>
                    <td><Clock size={11} style={{ verticalAlign: "-1px" }} /> {new Date(g.expiresAt).toLocaleString()}</td>
                    <td style={{ color: stateColor[g.state], fontWeight: 700 }}>{g.state}</td>
                    <td style={{ textAlign: "right" }}>
                      {g.state === "active" && canManage(c) && (
                        <button type="button" style={{ ...ghost, padding: "2px 8px" }} onClick={() => revoke(c.caseId, g.id)}><Ban size={12} /> Revoke</button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}

          {canManage(c) && <GrantForm caseId={c.caseId} onDone={(text, ok) => { setMsg({ text, ok }); load() }} />}
        </div>
      ))}
    </div>
  )
}

export default function CasesPage() {
  return (
    <ProtectedRoute roles={["admin", "investigator", "analyst", "judiciary", "auditor"]}>
      <CasesContent />
    </ProtectedRoute>
  )
}
