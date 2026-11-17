"use client"

import React, { useState } from "react"
import { Evidence, EvidenceStatus } from "@/types"
import { useAuth } from "@/context/AuthContext"
import styles from "./EvidenceCard.module.css"
import { Film, ImageIcon, FileText, Folder, CheckCircle, Flag, Loader2, AlertOctagon, Eye, ShieldCheck, XCircle, Scale, Lock, X } from "lucide-react"
import { signingPayloads } from "@/lib/didKeys"

interface VerificationResult {
  verified: boolean
  checks: Array<{ name: string; ok: boolean; detail: string }>
  timeline: Array<{ id: string; action: string; performedBy: string; timestamp: string; txHash: string; blockNumber?: number; ledgerMatch: boolean }>
  verificationTx: string
}

const fileTypeIcon: Record<string, React.ReactNode> = {
  "video/mp4":       <Film size={13} strokeWidth={1.5} />,
  "image/jpeg":      <ImageIcon size={13} strokeWidth={1.5} />,
  "image/png":       <ImageIcon size={13} strokeWidth={1.5} />,
  "application/pdf": <FileText size={13} strokeWidth={1.5} />,
}

interface EvidenceCardProps {
  evidence: Evidence
  onStatusChange?: (id: string, status: EvidenceStatus) => void
}

export default function EvidenceCard({ evidence, onStatusChange }: EvidenceCardProps) {
  const { role, status: userStatus, authFetch, signPayload } = useAuth()
  const [verification, setVerification] = useState<VerificationResult | null>(null)
  const approved = userStatus === "approved"
  const canFlag = approved && ["analyst", "judiciary", "admin"].includes(role)
  const canVerify = approved && ["judiciary", "admin"].includes(role)
  const canReadNotes = approved && ["investigator", "judiciary", "admin"].includes(role)
  const [privateNotes, setPrivateNotes] = useState<{ fileName: string; notes: string; hashMatches: boolean } | null>(null)
  const [currentStatus, setCurrentStatus] = useState<EvidenceStatus>(evidence.status || "pending")
  const [loadingAction, setLoadingAction] = useState<string | null>(null)
  const [actionMessage, setActionMessage] = useState<string | null>(null)
  const [rejectionAlert, setRejectionAlert] = useState<{
    httpStatus: number
    rule?: string
    reason: string
  } | null>(null)
  const [previewData, setPreviewData] = useState<{ url: string; type: string; name: string; tx?: string } | null>(null)

  React.useEffect(() => {
    setCurrentStatus(evidence.status || "pending")
    setRejectionAlert(null)
  }, [evidence.status, role, userStatus])

  const reject = async (res: Response, fallback: string) => {
    const errJson = await res.json().catch(() => ({}))
    setActionMessage(null)
    setRejectionAlert({ httpStatus: res.status, rule: errJson.opaDecision?.rule || errJson.code, reason: errJson.error || fallback })
  }

  /** In-browser view: access is audited on the ledger by the server before any byte is decrypted. */
  const handleView = async () => {
    try {
      setLoadingAction("view")
      setRejectionAlert(null)
      setActionMessage("Recording view on ledger...")
      const res = await authFetch(`/api/evidence/${evidence.id}/view`)
      if (!res.ok) {
        return reject(res, "View failed")
      }
      const raw = await res.blob()
      const type = (res.headers.get("Content-Type") || "").split(";")[0].trim().toLowerCase()
      const safeInline = /^(image\/(png|jpe?g|gif|webp|bmp)|video\/|audio\/|application\/pdf$|text\/plain$)/.test(type)
      const blob = new Blob([raw], { type: safeInline ? type : "text/plain" })
      const url = URL.createObjectURL(blob)
      const tx = res.headers.get("X-Ledger-Tx") || undefined
      setPreviewData({ url, type: safeInline ? type : "application/pdf", name: evidence.name || evidence.id, tx })
      setActionMessage(`Viewed; access recorded on ledger in tx ${tx ? tx.slice(0, 12) + "…" : ""}`)
      setTimeout(() => setActionMessage(null), 5000)
    } catch (err: any) {
      setActionMessage(err.message || "Request failed")
    } finally {
      setLoadingAction(null)
    }
  }

  /** Court report: PDF; its SHA-256 is written to the ledger before it is released. */
  const handleReport = async () => {
    try {
      setLoadingAction("report")
      setRejectionAlert(null)
      const res = await authFetch(`/api/evidence/${evidence.id}/report?format=pdf`)
      if (!res.ok) return reject(res, "Report export failed")
      const url = URL.createObjectURL(await res.blob())
      const a = document.createElement("a")
      a.href = url
      a.download = `custody-report-${evidence.id}.pdf`
      document.body.appendChild(a)
      a.click()
      a.remove()
      setTimeout(() => URL.revokeObjectURL(url), 60_000)
      setActionMessage(`Report sealed: SHA-256 ${String(res.headers.get("X-Report-SHA256")).slice(0, 12)}… recorded in tx ${String(res.headers.get("X-Ledger-Tx")).slice(0, 12)}…`)
    } finally {
      setLoadingAction(null)
    }
  }

  const handlePrivate = async () => {
    try {
      setLoadingAction("private")
      setRejectionAlert(null)
      const res = await authFetch(`/api/evidence/${evidence.id}/private`)
      if (!res.ok) return reject(res, "Private notes unavailable")
      setPrivateNotes((await res.json()).data)
    } finally {
      setLoadingAction(null)
    }
  }

  const handleVerify = async () => {
    try {
      setLoadingAction("integrity")
      setRejectionAlert(null)
      const res = await authFetch(`/api/evidence/${evidence.id}/verify`)
      if (!res.ok) return reject(res, "Verification failed")
      const json = await res.json()
      setVerification(json.data)
    } catch (err: any) {
      setActionMessage(err.message || "Verification failed")
    } finally {
      setLoadingAction(null)
    }
  }

  const handleStatusUpdate = async (newStatus: "verified" | "flagged") => {
    try {
      setLoadingAction(newStatus)
      setRejectionAlert(null)
      setActionMessage(null)
      // The status change is signed with your DID key; the server verifies it before touching the ledger.
      const signature = signPayload(signingPayloads.status(evidence.id, newStatus))
      const res = await authFetch(`/api/evidence/${evidence.id}/status`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus, signature })
      })

      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setRejectionAlert({
          httpStatus: res.status,
          rule: data.opaDecision?.rule,
          reason: data.error || data.message || "Status update rejected by server"
        })
        return
      }

      setCurrentStatus(newStatus)
      if (onStatusChange) {
        onStatusChange(evidence.id, newStatus)
      }
      setActionMessage(`Marked as ${newStatus} in block ${data.blockNumber} (tx ${String(data.txHash).slice(0, 12)}…)`)
      setTimeout(() => setActionMessage(null), 4000)
    } catch (err: any) {
      console.error("Status update error:", err)
      setActionMessage(err.message || "Status update failed")
      setTimeout(() => setActionMessage(null), 3000)
    } finally {
      setLoadingAction(null)
    }
  }

  return (
    <div className={styles.card}>
      <div className={styles.header}>
        <span className={styles.icon}>
          {fileTypeIcon[evidence.fileType] ?? <Folder size={13} strokeWidth={1.5} />}
        </span>
        <span className={styles.name}>{evidence.name}</span>
        <span className={`${styles.badge} ${styles[currentStatus] || styles.pending}`}>
          {currentStatus}
        </span>
      </div>

      <div className={styles.rows}>
        <div className={styles.row}>
          <span className={styles.label}>ID</span>
          <span className={styles.value}>{evidence.id}</span>
        </div>
        <div className={styles.row}>
          <span className={styles.label}>Case</span>
          <span className={styles.value}>{evidence.caseId}</span>
        </div>
        <div className={styles.row}>
          <span className={styles.label}>By</span>
          <span className={styles.value}>{evidence.uploadedBy}</span>
        </div>
        <div className={styles.row}>
          <span className={styles.label}>Time</span>
          <span className={styles.value}>
            {evidence.timestamp ? new Date(evidence.timestamp).toLocaleString() : "—"}
          </span>
        </div>
      </div>

      <div className={styles.hash} title={`Cryptographic SHA-256: ${evidence.hash}`}>
        {evidence.hash}
      </div>

      <div className={styles.actions}>
        <button type="button" className={`${styles.actionBtn} ${styles.inspectBtn}`} onClick={handleView} disabled={loadingAction !== null} title="View file in-browser; access is audited and committed to the ledger before rendering">
          {loadingAction === "view" ? <Loader2 size={12} className="animate-spin" /> : <Eye size={12} />}
          <span>View in Browser</span>
        </button>
        <button type="button" className={`${styles.actionBtn} ${styles.inspectBtn}`} onClick={handleVerify} disabled={loadingAction !== null} title="Recompute the hash and compare database, file and audit trail against the ledger">
          {loadingAction === "integrity" ? <Loader2 size={12} className="animate-spin" /> : <ShieldCheck size={12} />}
          <span>Verify integrity</span>
        </button>

        <button type="button" className={`${styles.actionBtn} ${styles.inspectBtn}`} onClick={handleReport} disabled={loadingAction !== null} title="Download a sealed courtroom report (PDF)">
          {loadingAction === "report" ? <Loader2 size={12} className="animate-spin" /> : <Scale size={12} />}
          <span>Court report</span>
        </button>

        {canReadNotes && (
          <button type="button" className={`${styles.actionBtn} ${styles.inspectBtn}`} onClick={handlePrivate} disabled={loadingAction !== null} title="Read case notes held in the ledger's private data collection">
            {loadingAction === "private" ? <Loader2 size={12} className="animate-spin" /> : <Lock size={12} />}
            <span>Private notes</span>
          </button>
        )}

        {canVerify && currentStatus !== "verified" && (
          <button type="button" className={`${styles.actionBtn} ${styles.verifyBtn}`} onClick={() => handleStatusUpdate("verified")} disabled={loadingAction !== null} title="Judicial sign-off (signed with your DID key)">
            {loadingAction === "verified" ? <Loader2 size={12} className="animate-spin" /> : <CheckCircle size={12} />}
            <span>Mark verified</span>
          </button>
        )}

        {canFlag && currentStatus !== "flagged" && (
          <button type="button" className={`${styles.actionBtn} ${styles.flagBtn}`} onClick={() => handleStatusUpdate("flagged")} disabled={loadingAction !== null} title="Flag an anomaly (signed with your DID key)">
            {loadingAction === "flagged" ? <Loader2 size={12} className="animate-spin" /> : <Flag size={12} />}
            <span>Flag</span>
          </button>
        )}
      </div>

      {privateNotes && (
        <div style={{ marginTop: "0.6rem", padding: "0.6rem 0.75rem", borderRadius: 6, fontSize: "0.76rem", background: "#f8fafc", border: "1px solid #cbd5e1", color: "#0f172a" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 700 }}>
            <span><Lock size={12} style={{ verticalAlign: "-1px" }} /> Private case notes {privateNotes.hashMatches ? "(match on-chain hash)" : "(DO NOT match on-chain hash)"}</span>
            <button type="button" onClick={() => setPrivateNotes(null)} style={{ background: "none", border: 0, cursor: "pointer" }}>×</button>
          </div>
          <div style={{ marginTop: 4 }}>Original file name: <code>{privateNotes.fileName}</code></div>
          <div style={{ marginTop: 4, whiteSpace: "pre-wrap" }}>{privateNotes.notes || <em>No notes recorded.</em>}</div>
          <div style={{ marginTop: 4, fontSize: "0.68rem", color: "#64748b" }}>This read was recorded on the ledger.</div>
        </div>
      )}

      {verification && (
        <div style={{ marginTop: "0.6rem", padding: "0.6rem 0.75rem", borderRadius: "6px", fontSize: "0.74rem", lineHeight: 1.45,
          background: verification.verified ? "#ecfdf5" : "#fef2f2", border: `1px solid ${verification.verified ? "#10b981" : "#ef4444"}`, color: verification.verified ? "#065f46" : "#991b1b" }}>
          <div style={{ display: "flex", justifyContent: "space-between", fontWeight: 700, marginBottom: 4 }}>
            <span>{verification.verified ? "Custody verified against the ledger" : "Verification FAILED"}</span>
            <button type="button" onClick={() => setVerification(null)} style={{ background: "none", border: 0, cursor: "pointer", color: "inherit" }}>×</button>
          </div>
          {verification.checks.map(c => (
            <div key={c.name} style={{ display: "flex", gap: 6, alignItems: "flex-start" }}>
              {c.ok ? <CheckCircle size={12} style={{ flexShrink: 0, marginTop: 2 }} /> : <XCircle size={12} style={{ flexShrink: 0, marginTop: 2 }} />}
              <span><strong>{c.name}</strong>: <span style={{ fontFamily: "monospace", wordBreak: "break-all" }}>{c.detail}</span></span>
            </div>
          ))}
          <details style={{ marginTop: 6 }}>
            <summary style={{ cursor: "pointer", fontWeight: 600 }}>Custody timeline ({verification.timeline.length} events)</summary>
            {verification.timeline.map(t => (
              <div key={t.id} style={{ fontFamily: "monospace", fontSize: "0.68rem", marginTop: 3 }}>
                {t.ledgerMatch ? "✓" : "✗"} {new Date(t.timestamp).toLocaleString()} · {t.action} · {t.performedBy} · block {t.blockNumber ?? "?"} · {String(t.txHash).slice(0, 10)}…
              </div>
            ))}
          </details>
          <div style={{ marginTop: 4, fontSize: "0.68rem", opacity: 0.8 }}>This check was itself recorded (tx {verification.verificationTx.slice(0, 12)}…).</div>
        </div>
      )}

      {actionMessage && (
        <span className={styles.actionStatus}>{actionMessage}</span>
      )}

      {rejectionAlert && (
        <div
          style={{
            marginTop: "0.6rem",
            padding: "0.6rem 0.75rem",
            background: "#fef2f2",
            border: "1px solid #ef4444",
            borderRadius: "6px",
            color: "#991b1b",
            fontSize: "0.75rem",
            lineHeight: 1.4
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "5px", fontWeight: 700, marginBottom: "2px" }}>
            <AlertOctagon size={13} />
            <span>
              HTTP {rejectionAlert.httpStatus} Rejected by Server
              {rejectionAlert.rule ? ` (${rejectionAlert.rule})` : ""}
            </span>
          </div>
          <div style={{ fontFamily: "monospace", fontSize: "0.72rem" }}>{rejectionAlert.reason}</div>
        </div>
      )}

      {/* In-Browser Modal Popup (No new window, no browser print/save toolbar) */}
      {previewData && (
        <div
          style={{
            position: "fixed",
            inset: 0,
            backgroundColor: "rgba(15, 23, 42, 0.75)",
            backdropFilter: "blur(4px)",
            zIndex: 99999,
            display: "flex",
            alignItems: "center",
            justifyContent: "center",
            padding: "1.5rem"
          }}
          onClick={() => {
            URL.revokeObjectURL(previewData.url)
            setPreviewData(null)
          }}
        >
          <div
            style={{
              backgroundColor: "#ffffff",
              borderRadius: "12px",
              boxShadow: "0 25px 50px -12px rgba(0, 0, 0, 0.25)",
              width: "100%",
              maxWidth: "1000px",
              maxHeight: "92vh",
              display: "flex",
              flexDirection: "column",
              overflow: "hidden",
              border: "1px solid #cbd5e1"
            }}
            onClick={e => e.stopPropagation()}
          >
            {/* Header */}
            <div
              style={{
                display: "flex",
                alignItems: "center",
                justifyContent: "space-between",
                padding: "0.85rem 1.25rem",
                borderBottom: "1px solid #e2e8f0",
                background: "#f8fafc"
              }}
            >
              <div>
                <div style={{ fontWeight: 700, fontSize: "0.95rem", color: "#0f172a", display: "flex", alignItems: "center", gap: "8px" }}>
                  <ShieldCheck size={16} color="#16a34a" />
                  <span>{previewData.name}</span>
                  <span style={{ fontSize: "0.72rem", background: "#e2e8f0", padding: "2px 6px", borderRadius: "4px", color: "#475569" }}>
                    {evidence.id}
                  </span>
                </div>
                {previewData.tx && (
                  <div style={{ fontSize: "0.7rem", color: "#64748b", marginTop: "2px" }}>
                    Audited on Fabric Ledger · Tx: <code style={{ fontSize: "0.68rem" }}>{previewData.tx.slice(0, 16)}…</code>
                  </div>
                )}
              </div>
              <button
                type="button"
                onClick={() => {
                  URL.revokeObjectURL(previewData.url)
                  setPreviewData(null)
                }}
                style={{
                  background: "#fee2e2",
                  color: "#991b1b",
                  border: "1px solid #fecaca",
                  borderRadius: "6px",
                  padding: "6px 12px",
                  cursor: "pointer",
                  display: "flex",
                  alignItems: "center",
                  gap: "4px",
                  fontSize: "0.8rem",
                  fontWeight: 700
                }}
              >
                <X size={15} /> Close
              </button>
            </div>

            {/* Content Preview */}
            <div
              style={{
                padding: "0.5rem",
                flex: 1,
                overflow: "auto",
                display: "flex",
                alignItems: "center",
                justifyContent: "center",
                background: "#0f172a"
              }}
            >
              {previewData.type.startsWith("image/") ? (
                <img
                  src={previewData.url}
                  alt={previewData.name}
                  style={{ maxWidth: "100%", maxHeight: "78vh", objectFit: "contain", borderRadius: "6px" }}
                />
              ) : previewData.type.startsWith("video/") ? (
                <video
                  src={previewData.url}
                  controls
                  controlsList="nodownload"
                  style={{ maxWidth: "100%", maxHeight: "78vh", borderRadius: "6px" }}
                />
              ) : previewData.type.startsWith("audio/") ? (
                <audio
                  src={previewData.url}
                  controls
                  controlsList="nodownload"
                  style={{ width: "100%", maxWidth: "500px" }}
                />
              ) : (
                <iframe
                  src={`${previewData.url}#toolbar=0&navpanes=0`}
                  title={previewData.name}
                  style={{
                    width: "100%",
                    height: "78vh",
                    border: "none",
                    borderRadius: "6px",
                    backgroundColor: "#ffffff"
                  }}
                />
              )}
            </div>
          </div>
        </div>
      )}
    </div>
  )
}