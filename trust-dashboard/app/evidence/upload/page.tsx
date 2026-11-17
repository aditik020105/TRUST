"use client"

import React, { useState, useEffect } from "react"
import Link from "next/link"
import { CheckCircle, ArrowRight, UploadCloud, RefreshCw, AlertOctagon } from "lucide-react"
import ProtectedRoute from "@/components/ProtectedRoute"
import { useAuth } from "@/context/AuthContext"
import { sha256Hex, signingPayloads } from "@/lib/didKeys"
import styles from "./page.module.css"

interface UploadReceipt {
  id: string
  caseId: string
  name: string
  hash: string
  txHash?: string
  blockNumber?: number
  didSignature?: string | null
  signatureVerified?: boolean
  uploadedBy: string
}

function UploadEvidenceContent() {
  const { did, role, mspId, status: userStatus, authFetch, signPayload } = useAuth()
  const [form, setForm] = useState<{ caseId: string; uploadedBy: string; file: File | null; notes: string }>({
    caseId: "",
    uploadedBy: "",
    file: null,
    notes: ""
  })
  const [receipt, setReceipt] = useState<UploadReceipt | null>(null)
  const [submitting, setSubmitting] = useState(false)
  const [error, setError] = useState("")
  const [opaRejection, setOpaRejection] = useState<{
    httpStatus: number
    rule?: string
    reason: string
  } | null>(null)

  useEffect(() => {
    if (did) {
      setForm(prev => ({ ...prev, uploadedBy: did }))
      setOpaRejection(null)
      setError("")
    }
  }, [did, role, userStatus])

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault()
    setError("")
    setOpaRejection(null)
    setSubmitting(true)

    try {
      if (!form.file) throw new Error("Choose a file")
      const caseId = form.caseId.trim()
      // Hash and sign in the browser: the server recomputes the hash and checks this signature
      // against your DID Document, so nobody else can submit evidence in your name.
      const fileHash = await sha256Hex(form.file)
      const signature = signPayload(signingPayloads.upload(caseId, fileHash))

      const formData = new FormData()
      formData.append("caseId", caseId)
      formData.append("signature", signature)
      if (form.notes.trim()) formData.append("notes", form.notes.trim())
      formData.append("file", form.file)

      const res = await authFetch("/api/evidence/upload", { method: "POST", body: formData })

      const data = await res.json().catch(() => ({}))

      if (res.ok && data.data) {
        setReceipt({
          id: data.data.id,
          caseId: data.data.caseId,
          name: data.data.name,
          hash: data.data.hash,
          txHash: data.txHash,
          blockNumber: data.blockNumber,
          didSignature: data.didSignature,
          signatureVerified: data.signatureCheck?.verified,
          uploadedBy: data.data.uploadedBy
        })
      } else {
        setOpaRejection({
          httpStatus: res.status,
          rule: data.opaDecision?.rule,
          reason: data.error || data.message || "Failed to upload evidence."
        })
      }
    } catch (err: any) {
      console.error("Upload error:", err)
      setError(err.message || "An error occurred during upload.")
    } finally {
      setSubmitting(false)
    }
  }

  const handleReset = () => {
    setReceipt(null)
    setForm(prev => ({ ...prev, file: null, notes: "" }))
  }

  return (
    <div className={styles.wrapper}>
      <h1 className={styles.heading}>Upload Digital Evidence</h1>

      {opaRejection && (
        <div
          style={{
            background: "#fef2f2",
            border: "2px solid #ef4444",
            borderRadius: "10px",
            padding: "1rem 1.25rem",
            marginBottom: "1.25rem",
            color: "#7f1d1d"
          }}
        >
          <div style={{ display: "flex", alignItems: "center", gap: "8px", fontWeight: 700, color: "#b91c1c", marginBottom: "4px" }}>
            <AlertOctagon size={18} />
            <span>
              HTTP {opaRejection.httpStatus} — Upload Rejected by Backend Server
              {opaRejection.rule ? ` [OPA Rule: ${opaRejection.rule}]` : ""}
            </span>
          </div>
          <div style={{ fontFamily: "monospace", fontSize: "0.84rem", background: "rgba(239,68,68,0.08)", padding: "0.6rem", borderRadius: "6px" }}>
            {opaRejection.reason}
          </div>
          <div style={{ fontSize: "0.76rem", marginTop: "6px" }}>
            Caller DID: <code>{did}</code> | Role: <code>{role} ({mspId})</code> | Status: <code>{userStatus}</code>
          </div>
        </div>
      )}

      {receipt ? (
        <div className={styles.receiptCard}>
          <div className={styles.successHeader}>
            <CheckCircle size={28} />
            <div>
              <strong style={{ fontSize: "1.1rem" }}>Evidence Anchored to Ledger &amp; Signed by W3C DID</strong>
              <p style={{ marginTop: "3px", fontSize: "0.85rem", color: "#475569" }}>
                File encrypted with AES-256-GCM; its SHA-256 digest and your Ed25519 signature were committed to the ledger.
              </p>
            </div>
          </div>

          <div className={styles.receiptRows}>
            <div className={styles.receiptRow}>
              <span className={styles.receiptLabel}>Evidence Identifier</span>
              <span className={styles.receiptValue}>{receipt.id}</span>
            </div>

            <div className={styles.receiptRow}>
              <span className={styles.receiptLabel}>Case ID</span>
              <span className={styles.receiptValue}>{receipt.caseId}</span>
            </div>

            <div className={styles.receiptRow}>
              <span className={styles.receiptLabel}>Original File</span>
              <span className={styles.receiptValue}>{receipt.name}</span>
            </div>

            <div className={styles.receiptRow}>
              <span className={styles.receiptLabel}>SHA-256 Digest (Buffer Hash)</span>
              <span className={styles.receiptValue}>{receipt.hash}</span>
            </div>

            {receipt.didSignature && (
              <div className={styles.receiptRow}>
                <span className={styles.receiptLabel}>Ed25519 DID Signature {receipt.signatureVerified ? "(verified by server)" : ""}</span>
                <span className={styles.receiptValue} style={{ wordBreak: "break-all" }}>
                  {receipt.didSignature.slice(0, 48)}...
                </span>
              </div>
            )}

            <div className={styles.receiptRow}>
              <span className={styles.receiptLabel}>Ledger Transaction{receipt.blockNumber !== undefined ? ` (block ${receipt.blockNumber})` : ""}</span>
              <span className={`${styles.receiptValue} ${styles.receiptTx}`}>
                {receipt.txHash}
              </span>
            </div>

            <div className={styles.receiptRow}>
              <span className={styles.receiptLabel}>Custodian W3C DID &amp; Organization</span>
              <span className={styles.receiptValue}>
                {receipt.uploadedBy} ({mspId})
              </span>
            </div>
          </div>

          <div className={styles.receiptActions}>
            <Link href="/dashboard" className={styles.primaryBtn}>
              View in Dashboard <ArrowRight size={15} style={{ marginLeft: "4px" }} />
            </Link>
            <button type="button" onClick={handleReset} className={styles.secondaryBtn}>
              <RefreshCw size={14} style={{ marginRight: "6px", display: "inline" }} />
              Upload Another File
            </button>
          </div>
        </div>
      ) : (
        <form className={styles.form} onSubmit={handleSubmit}>
          {error && <p style={{ color: "#ef4444", fontSize: "0.85rem" }}>{error}</p>}
          <label>
            Case ID
            <input
              required
              placeholder="e.g. CASE-2026-004"
              value={form.caseId}
              onChange={e => setForm({ ...form, caseId: e.target.value })}
            />
          </label>
          <label>
            Uploaded By (your DID; set by the server from your session)
            <input
              value={did}
              readOnly
              style={{ backgroundColor: "#f8fafc", color: "#64748b" }}
            />
          </label>
          <label>
            Private case notes (optional)
            <textarea
              rows={3}
              maxLength={4000}
              placeholder="e.g. witness names, informant details. Kept only by Police and Judiciary peers in the ledger's private data collection; never stored in the database."
              value={form.notes}
              onChange={e => setForm({ ...form, notes: e.target.value })}
              style={{ fontFamily: "inherit", fontSize: "0.85rem", padding: "0.5rem", borderRadius: 6, border: "1px solid #cbd5e1" }}
            />
          </label>
          <label>
            Select Evidence Binary File
            <input
              type="file"
              required
              onChange={e => setForm({ ...form, file: e.target.files?.[0] ?? null })}
            />
          </label>
          <button type="submit" disabled={submitting}>
            {submitting ? (
              "Evaluating OPA & Signing with Ed25519 DID..."
            ) : (
              <>
                <UploadCloud size={18} /> Submit &amp; Anchor Evidence
              </>
            )}
          </button>
        </form>
      )}
    </div>
  )
}

export default function UploadEvidence() {
  return (
    <ProtectedRoute roles={["investigator", "analyst", "admin"]}>
      <UploadEvidenceContent />
    </ProtectedRoute>
  )
}