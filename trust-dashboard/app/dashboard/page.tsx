"use client"

import { useEffect, useState } from "react"
import Link from "next/link"
import { Evidence } from "@/types"
import EvidenceCard from "@/components/EvidenceCard"
import ProtectedRoute from "@/components/ProtectedRoute"
import { useAuth } from "@/context/AuthContext"
import styles from "./page.module.css"
import { Folder, FolderOpen, ChevronDown, AlertOctagon, ShieldCheck, Key } from "lucide-react"

function DashboardContent() {
  const [evidence, setEvidence] = useState<Evidence[]>([])
  const [loading, setLoading] = useState(true)
  const [serverRejection, setServerRejection] = useState<{
    httpStatus: number
    rule?: string
    reason: string
    details?: any
  } | null>(null)
  const [openCase, setOpenCase] = useState<string | null>(null)
  const [tabs, setTabs] = useState<Record<string, "role" | "type">>({})
  const { user, role, did, mspId, status: userStatus, getIdToken } = useAuth()

  useEffect(() => {
    async function loadEvidence() {
      setLoading(true)
      setServerRejection(null)
      try {
        const token = await getIdToken()
        const headers: Record<string, string> = {}
        if (token) {
          headers["Authorization"] = `Bearer ${token}`
        }

        const apiUrl = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001"
        const res = await fetch(`${apiUrl}/api/evidence`, { headers })
        const json = await res.json().catch(() => ({}))

        if (!res.ok) {
          setEvidence([])
          setServerRejection({
            httpStatus: res.status,
            rule: json.opaDecision?.rule,
            reason: json.error || json.message || "Server rejected request",
            details: json.opaDecision?.evaluatedContext
          })
        } else if (Array.isArray(json.data)) {
          setEvidence(json.data)
          if (json.data.length > 0 && !openCase) {
            setOpenCase(json.data[0].caseId || "UNCATEGORIZED")
          }
        }
      } catch (err: any) {
        console.error("Error fetching evidence:", err)
      } finally {
        setLoading(false)
      }
    }

    loadEvidence()
  }, [user?.uid, role, did, userStatus])

  const handleStatusChange = (id: string, newStatus: "verified" | "pending" | "flagged") => {
    setEvidence(prev => prev.map(item => item.id === id ? { ...item, status: newStatus } : item))
  }

  const total = evidence.length
  const verified = evidence.filter(e => e.status === "verified").length
  const pending = evidence.filter(e => e.status === "pending").length

  const caseMap: Record<string, Evidence[]> = {}
  for (const ev of evidence) {
    const cId = ev.caseId || "UNCATEGORIZED"
    if (!caseMap[cId]) caseMap[cId] = []
    caseMap[cId].push(ev)
  }

  function getRoleFromDID(didStr?: string): string {
    const s = String(didStr || "").toLowerCase()
    if (s.includes("investigator") || s.includes("officer")) return "Investigator (Police)"
    if (s.includes("analyst") || s.includes("forensic")) return "Forensic Analyst"
    if (s.includes("judiciary") || s.includes("judge")) return "Judiciary / Court"
    if (s.includes("admin")) return "Consortium Admin"
    return "Other Custodian"
  }

  function getTab(caseId: string): "role" | "type" {
    return tabs[caseId] ?? "role"
  }

  function setTab(caseId: string, tab: "role" | "type") {
    setTabs(prev => ({ ...prev, [caseId]: tab }))
  }

  const safeStatus = userStatus || "approved"

  if (loading) return <p className={styles.loading}>Loading evidence ledger &amp; evaluating OPA policy...</p>

  return (
    <div>
      <div className={styles.topBar}>
        <div>
          <h1 className={styles.heading}>Evidence Dashboard</h1>
          <p className={styles.subheading}>
            Active Identity: <code>{did || "did:trust:investigator01"}</code> • Role: <strong>{role || "investigator"}</strong> ({mspId || "PoliceOrgMSP"}) • Authorization:{" "}
            <strong
              style={{
                color:
                  safeStatus === "approved"
                    ? "#16a34a"
                    : safeStatus === "pending"
                    ? "#d97706"
                    : "#dc2626"
              }}
            >
              {String(safeStatus).toUpperCase()}
            </strong>
          </p>
        </div>
        {["admin", "auditor"].includes(role) && userStatus === "approved" && (
        <Link
          href="/admin"
          style={{
            display: "inline-flex",
            alignItems: "center",
            gap: "6px",
            padding: "0.55rem 1rem",
            background: "#7f1d1d",
            color: "#fff",
            borderRadius: "8px",
            fontSize: "0.82rem",
            fontWeight: 600,
            textDecoration: "none"
          }}
        >
          <Key size={14} />
          <span>{role === "admin" ? "Admin, OPA & Firewall" : "Oversight"}</span>
        </Link>
        )}
      </div>

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
              HTTP {serverRejection.httpStatus} — Request Rejected by Backend Server
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
          <div style={{ marginTop: "1rem", fontSize: "0.85rem" }}>
            {userStatus === "pending"
              ? "Your account is waiting for an administrator to approve it. Reload this page after approval."
              : userStatus === "revoked"
              ? "Your DID has been revoked. Contact an administrator."
              : null}
          </div>
        </div>
      ) : (
        <>
          <div className={styles.statsRow}>
            <div className={styles.statCard}>
              <span className={styles.statNumber}>{total}</span>
              <span className={styles.statLabel}>Total Evidence</span>
            </div>
            <div className={`${styles.statCard} ${styles.green}`}>
              <span className={styles.statNumber}>{verified}</span>
              <span className={styles.statLabel}>Verified</span>
            </div>
            <div className={`${styles.statCard} ${styles.yellow}`}>
              <span className={styles.statNumber}>{pending}</span>
              <span className={styles.statLabel}>Pending</span>
            </div>
          </div>

          <div className={styles.caseList}>
            {Object.keys(caseMap).length === 0 ? (
              <div style={{ textAlign: "center", padding: "3rem", color: "#94a3b8" }}>
                No evidence files registered yet. Upload evidence to get started.
              </div>
            ) : (
              Object.entries(caseMap).map(([caseId, items]) => {
                const isOpen = openCase === caseId
                const tab = getTab(caseId)
                const verifiedCount = items.filter(e => e.status === "verified").length
                const pendingCount = items.filter(e => e.status === "pending").length

                return (
                  <div key={caseId} className={`${styles.caseFolder} ${isOpen ? styles.caseFolderOpen : ""}`}>
                    <button
                      className={styles.caseFolderHeader}
                      onClick={() => setOpenCase(isOpen ? null : caseId)}
                    >
                      <span className={`${styles.folderIcon} ${isOpen ? styles.folderIconOpen : ""}`}>
                        {isOpen
                          ? <FolderOpen size={15} strokeWidth={1.4} />
                          : <Folder size={15} strokeWidth={1.4} />
                        }
                      </span>

                      <span className={styles.caseMeta}>
                        <span className={styles.caseId}>{caseId}</span>
                        <span className={styles.caseSub}>{items.length} evidence item{items.length !== 1 ? "s" : ""}</span>
                      </span>

                      <span className={styles.casePills}>
                        {verifiedCount > 0 && (
                          <span className={`${styles.casePill} ${styles.pillVerified}`}>{verifiedCount} verified</span>
                        )}
                        {pendingCount > 0 && (
                          <span className={`${styles.casePill} ${styles.pillPending}`}>{pendingCount} pending</span>
                        )}
                      </span>

                      <span className={`${styles.chevron} ${isOpen ? styles.chevronOpen : ""}`}>
                        <ChevronDown size={14} strokeWidth={1.5} />
                      </span>
                    </button>

                    {isOpen && (
                      <div className={styles.caseFolderBody}>
                        <div className={styles.tabs}>
                          <button
                            className={`${styles.tab} ${tab === "role" ? styles.activeTab : ""}`}
                            onClick={() => setTab(caseId, "role")}
                          >
                            By role
                          </button>
                          <button
                            className={`${styles.tab} ${tab === "type" ? styles.activeTab : ""}`}
                            onClick={() => setTab(caseId, "type")}
                          >
                            By file type
                          </button>
                        </div>

                        <div className={styles.caseContent}>
                          {tab === "role" && (() => {
                            const byRole: Record<string, Evidence[]> = {}
                            for (const ev of items) {
                              const r = getRoleFromDID(ev.uploadedBy)
                              if (!byRole[r]) byRole[r] = []
                              byRole[r].push(ev)
                            }
                            return (
                              <div className={styles.group}>
                                <div className={styles.grid}>
                                  {Object.entries(byRole).map(([r, evs]) =>
                                    evs.map(ev => (
                                      <div key={ev.id} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                                        <p className={styles.groupLabel}>{r}</p>
                                        <EvidenceCard evidence={ev} onStatusChange={handleStatusChange} />
                                      </div>
                                    ))
                                  )}
                                </div>
                              </div>
                            )
                          })()}

                          {tab === "type" && (() => {
                            const byType: Record<string, Evidence[]> = {}
                            for (const ev of items) {
                              const rawType = ev.fileType || "application/octet-stream"
                              const type = rawType.split("/")[1] ?? rawType
                              if (!byType[type]) byType[type] = []
                              byType[type].push(ev)
                            }
                            return (
                              <div className={styles.group}>
                                <div className={styles.grid}>
                                  {Object.entries(byType).map(([type, evs]) =>
                                    evs.map(ev => (
                                      <div key={ev.id} style={{ display: "flex", flexDirection: "column", gap: "4px" }}>
                                        <p className={styles.groupLabel}>{type}</p>
                                        <EvidenceCard evidence={ev} onStatusChange={handleStatusChange} />
                                      </div>
                                    ))
                                  )}
                                </div>
                              </div>
                            )
                          })()}
                        </div>
                      </div>
                    )}
                  </div>
                )
              })
            )}
          </div>
        </>
      )}
    </div>
  )
}

export default function Dashboard() {
  return (
    <ProtectedRoute>
      <DashboardContent />
    </ProtectedRoute>
  )
}