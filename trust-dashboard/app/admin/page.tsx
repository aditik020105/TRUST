"use client"

import React, { useEffect, useState } from "react"
import { useAuth } from "@/context/AuthContext"
import { UserProfile, DIDDocument } from "@/types"
import ProtectedRoute from "@/components/ProtectedRoute"
import { RecoveryPanel, DataPanel } from "@/components/AdminExtras"
import {
  ShieldAlert,
  ShieldCheck,
  UserCheck,
  UserX,
  Key,
  FileCode,
  Flame,
  RefreshCw,
  CheckCircle,
  AlertOctagon,
  Play,
  Unlock,
  Link2
} from "lucide-react"
import styles from "./page.module.css"

function AdminDashboardContent() {
  const { user, role, did, status, getIdToken, refreshUserStatus, authFetch, signPayload } = useAuth()
  const isAdmin = role === "admin"
  const [activeTab, setActiveTab] = useState<"users" | "opa" | "firewall" | "ledger" | "recovery" | "data">(role === "admin" ? "users" : "opa")
  const [ledger, setLedger] = useState<any>(null)
  const [reconcile, setReconcile] = useState<any>(null)

  // Users & DID state
  const [users, setUsers] = useState<UserProfile[]>([])
  const [selectedDidDoc, setSelectedDidDoc] = useState<DIDDocument | null>(null)
  const [verifyResult, setVerifyResult] = useState<any>(null)

  // OPA state
  const [opaData, setOpaData] = useState<{
    regoPolicy: string
    roleAccessMatrix: any[]
    decisionLogs: any[]
    rejectedLogs: any[]
  }>({
    regoPolicy: "",
    roleAccessMatrix: [],
    decisionLogs: [],
    rejectedLogs: []
  })
  const [simRole, setSimRole] = useState("investigator")
  const [simStatus, setSimStatus] = useState("approved")
  const [simAction, setSimAction] = useState("update_evidence_status")
  const [simTargetStatus, setSimTargetStatus] = useState("verified")
  const [simResult, setSimResult] = useState<any>(null)

  // Firewall state
  const [firewall, setFirewall] = useState<any>(null)
  const [burstResult, setBurstResult] = useState<any>(null)

  // Alerts
  const [serverRejection, setServerRejection] = useState<{
    title: string
    reason: string
    rule?: string
    details?: any
  } | null>(null)
  const [successMsg, setSuccessMsg] = useState<string | null>(null)
  const [loading, setLoading] = useState(false)

  const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001"

  async function fetchAdminData() {
    try {
      const none = new Response("{}", { status: 200, headers: { "Content-Type": "application/json" } })
      const [usersRes, opaRes, fwRes, ledgerRes] = await Promise.all([
        isAdmin ? authFetch("/api/admin/users") : Promise.resolve(none.clone()),
        authFetch("/api/admin/opa"),
        isAdmin ? authFetch("/api/admin/firewall") : Promise.resolve(none.clone()),
        authFetch("/api/admin/ledger")
      ])
      const ledgerJson = await ledgerRes.json().catch(() => ({}))
      if (ledgerJson.data) {
        setLedger(ledgerJson.data)
        if (ledgerJson.data.lastReconciliation) setReconcile(ledgerJson.data.lastReconciliation)
      }

      const usersJson = await usersRes.json().catch(() => ({}))
      if (Array.isArray(usersJson.data)) setUsers(usersJson.data)

      const opaJson = await opaRes.json().catch(() => ({}))
      if (opaJson.data) {
        setOpaData({
          regoPolicy: opaJson.data.regoPolicy || "",
          roleAccessMatrix: Array.isArray(opaJson.data.roleAccessMatrix) ? opaJson.data.roleAccessMatrix : [],
          decisionLogs: Array.isArray(opaJson.data.decisionLogs) ? opaJson.data.decisionLogs : [],
          rejectedLogs: Array.isArray(opaJson.data.rejectedLogs) ? opaJson.data.rejectedLogs : []
        })
      }

      const fwJson = await fwRes.json().catch(() => ({}))
      if (fwJson.data) setFirewall(fwJson.data)
    } catch (err) {
      console.error("Failed loading admin data:", err)
    }
  }

  useEffect(() => {
    fetchAdminData()
  }, [user?.uid, role, status])

  const handleAuthorizeUser = async (
    targetUid: string,
    newStatus?: "approved" | "pending" | "revoked",
    newRole?: string
  ) => {
    setServerRejection(null)
    setSuccessMsg(null)
    setLoading(true)

    try {
      const res = await authFetch(`/api/admin/users/${targetUid}/authorize`, {
        method: "PATCH",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ status: newStatus, role: newRole })
      })

      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setServerRejection({
          title: `HTTP ${res.status} — Server Rejected Authorization Change`,
          reason: data.error || "Authorization update rejected by OPA policy.",
          rule: data.opaDecision?.rule,
          details: data.opaDecision?.evaluatedContext
        })
      } else {
        setSuccessMsg(
          `${data.message} (ledger tx ${data.txHash ? data.txHash.slice(0, 22) + "…" : ""})`
        )
        await refreshUserStatus()
      }
      await fetchAdminData()
    } catch (err: any) {
      setServerRejection({
        title: "Network / Server Error",
        reason: err.message
      })
    } finally {
      setLoading(false)
    }
  }

  /**
   * Signs a fresh challenge with YOUR key (held only in this browser) and asks the server to verify it
   * against the selected DID Document. It succeeds for your own DID and fails for anyone else's,
   * which is the impersonation check the login flow relies on. There is no server-side signing.
   */
  const handleTestEd25519Verify = async (targetDid: string) => {
    setVerifyResult(null)
    try {
      const challenge = `TRUST-CUSTODY-CHALLENGE-${Date.now()}`
      const signatureHex = signPayload(challenge)
      const verifyRes = await fetch(`${API_URL}/api/did/verify`, {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ did: targetDid, payload: challenge, signatureHex })
      })
      const verifyJson = await verifyRes.json().catch(() => ({}))
      setVerifyResult({ challenge, signatureHex, signedBy: did, ...(verifyJson.data || {}) })
    } catch (err: any) {
      setVerifyResult({ verified: false, reason: err.message })
    }
  }

  const handleReconcile = async () => {
    setLoading(true)
    try {
      const res = await authFetch("/api/admin/reconcile", { method: "POST" })
      const json = await res.json().catch(() => ({}))
      if (json.data) setReconcile(json.data)
      await fetchAdminData()
    } finally {
      setLoading(false)
    }
  }

  const handleSimulateOpa = async (e: React.FormEvent) => {
    e.preventDefault()
    setSimResult(null)
    try {
      const res = await authFetch("/api/admin/opa/evaluate", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({
          role: simRole,
          status: simStatus,
          action: simAction,
          parameters: simAction === "update_evidence_status" ? { status: simTargetStatus } : {}
        })
      })
      const data = await res.json().catch(() => ({}))
      setSimResult({
        // dry-run: the endpoint always answers 200; show the status the real request would get
        httpStatus: res.ok ? (data.data?.allow ? 200 : 403) : res.status,
        ...(data.data || {})
      })
      await fetchAdminData()
    } catch (err: any) {
      console.error("OPA simulation error:", err)
    }
  }

  const handleSimulateFirewallBurst = async () => {
    setBurstResult(null)
    setServerRejection(null)
    setLoading(true)
    try {
      let allowedCount = 0
      let throttledCount = 0
      let lastBlockedPayload: any = null
      let lastHeaders: Record<string, string | null> = {}

      // Send 35 rapid requests to exceed MAX_REQUESTS (30) in 10s window (below the 50-request jail,
      // so this demo never counts as a flood warning against your own DID)
      const token = await getIdToken()
      for (let i = 1; i <= 35; i++) {
        const res = await fetch(`${API_URL}/api/evidence`, { headers: token ? { Authorization: `Bearer ${token}` } : {} })
        if (res.status === 200) {
          allowedCount++
        } else if (res.status === 429) {
          throttledCount++
          lastBlockedPayload = await res.json().catch(() => ({}))
          lastHeaders = {
            "Retry-After": res.headers.get("Retry-After"),
            "X-RateLimit-Limit": res.headers.get("X-RateLimit-Limit"),
            "X-RateLimit-Remaining": res.headers.get("X-RateLimit-Remaining"),
            "X-DDoS-Protection": res.headers.get("X-DDoS-Protection")
          }
        }
      }

      setBurstResult({
        totalSent: 35,
        allowedCount,
        throttledCount,
        lastBlockedPayload,
        lastHeaders
      })

      // Refresh only /api/admin/firewall (exempted from rate limiter) so burst logs stay exact
      const fwRes = await authFetch("/api/admin/firewall")
      const fwJson = await fwRes.json().catch(() => ({}))
      if (fwJson.data) setFirewall(fwJson.data)
    } catch (err: any) {
      console.error("Firewall burst test error:", err)
    } finally {
      setLoading(false)
    }
  }

  const handleResetFirewall = async (ip?: string) => {
    setServerRejection(null)
    setSuccessMsg(null)
    setLoading(true)
    try {
      const res = await authFetch("/api/admin/firewall/reset", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify(ip ? { ip } : {})
      })
      const data = await res.json().catch(() => ({}))
      if (!res.ok) {
        setServerRejection({
          title: `HTTP ${res.status} — Server Rejected Firewall Reset`,
          reason: data.error || "Firewall reset rejected by OPA policy.",
          rule: data.opaDecision?.rule,
          details: data.opaDecision?.evaluatedContext
        })
      } else {
        setBurstResult(null)
        setSuccessMsg(ip ? `Unbanned IP ${ip}` : "Firewall counters and jailed IPs reset.")
      }
      await fetchAdminData()
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.container}>
      <div className={styles.header}>
        <div>
          <h1 className={styles.title}>Security, DID &amp; OPA Control Center</h1>
          <p className={styles.subtitle}>
            Manage User Authorization (Approve / Revoke), W3C Ed25519 DIDs, Open Policy Agent (`.rego`) Rules &amp; Firewall Requests
          </p>
        </div>
        <button
          type="button"
          className={styles.btnSecondary}
          onClick={fetchAdminData}
          style={{ display: "inline-flex", alignItems: "center", gap: "6px", padding: "0.55rem 0.9rem" }}
        >
          <RefreshCw size={14} />
          <span>Refresh Live Telemetry</span>
        </button>
      </div>

      {serverRejection && (
        <div className={styles.rejectionBanner}>
          <div className={styles.rejectionTitle}>
            <AlertOctagon size={18} />
            <span>{serverRejection.title}</span>
          </div>
          <div className={styles.rejectionReason}>{serverRejection.reason}</div>
          {serverRejection.rule && (
            <div style={{ fontSize: "0.78rem", marginTop: "4px" }}>
              <strong>Triggered OPA Rule:</strong> <code>{serverRejection.rule}</code> |{" "}
              <strong>Active Caller:</strong> <code>{did} ({role}, status={status})</code>
            </div>
          )}
        </div>
      )}

      {successMsg && (
        <div className={styles.successBanner}>
          <div style={{ display: "flex", alignItems: "center", gap: "8px" }}>
            <CheckCircle size={18} />
            <span>{successMsg}</span>
          </div>
          <button
            type="button"
            onClick={() => setSuccessMsg(null)}
            className={styles.btnSecondary}
          >
            Dismiss
          </button>
        </div>
      )}

      <div className={styles.tabs}>
        {isAdmin && (
        <button
          type="button"
          className={`${styles.tabBtn} ${activeTab === "users" ? styles.tabActive : ""}`}
          onClick={() => setActiveTab("users")}
        >
          <Key size={15} />
          <span>1. User Approve / Revoke &amp; Real W3C DIDs ({users.length})</span>
        </button>
        )}

        <button
          type="button"
          className={`${styles.tabBtn} ${activeTab === "opa" ? styles.tabActive : ""}`}
          onClick={() => setActiveTab("opa")}
        >
          <FileCode size={15} />
          <span>2. OPA Rules (`.rego`), Role Parameters &amp; Server Rejections ({opaData.rejectedLogs.length})</span>
        </button>

        {isAdmin && (
        <button
          type="button"
          className={`${styles.tabBtn} ${activeTab === "firewall" ? styles.tabActive : ""}`}
          onClick={() => setActiveTab("firewall")}
        >
          <Flame size={15} />
          <span>3. Firewall &amp; DDoS Requests ({firewall?.recentLogs?.length || 0})</span>
        </button>
        )}

        <button
          type="button"
          className={`${styles.tabBtn} ${activeTab === "ledger" ? styles.tabActive : ""}`}
          onClick={() => setActiveTab("ledger")}
        >
          <Link2 size={15} />
          <span>4. Ledger &amp; Reconciliation {reconcile ? (reconcile.ok ? "✓" : `(${reconcile.issues?.length || "!"})`) : ""}</span>
        </button>

        {isAdmin && (
          <button type="button" className={`${styles.tabBtn} ${activeTab === "recovery" ? styles.tabActive : ""}`} onClick={() => setActiveTab("recovery")}>
            <Key size={15} />
            <span>5. Key Recovery</span>
          </button>
        )}

        {isAdmin && (
          <button type="button" className={`${styles.tabBtn} ${activeTab === "data" ? styles.tabActive : ""}`} onClick={() => setActiveTab("data")}>
            <FileCode size={15} />
            <span>6. Legacy Import &amp; Connector</span>
          </button>
        )}
      </div>

      {/* =====================================================================
          TAB 1: USER AUTHORIZATION (APPROVE / REVOKE) & W3C DID REGISTRY
         ===================================================================== */}
      {activeTab === "users" && (
        <>
          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>
              <ShieldCheck size={18} style={{ color: "#991b1b" }} />
              <span>Agency Identity Registry — Approve / Revoke Users &amp; Manage Roles</span>
            </h2>
            <p className={styles.sectionDesc}>
              Every user is bound to an Ed25519 asymmetric cryptographic keypair and a W3C DID v1.0 Document.
              Approving or revoking a user anchors an authorization transaction on Hyperledger Fabric and immediately updates OPA policy enforcement.
              (Note: Only <code>admin</code> or <code>judiciary</code> can approve/revoke; try clicking Approve/Revoke while switched to <code>investigator</code> to see the server 403 rejection!)
            </p>

            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Officer / Identity</th>
                    <th>W3C Decentralized Identifier (DID)</th>
                    <th>Role &amp; Fabric MSP</th>
                    <th>Auth Status</th>
                    <th>Ed25519 Fingerprint / Fabric Tx</th>
                    <th>Authorization Controls (Approve / Revoke)</th>
                  </tr>
                </thead>
                <tbody>
                  {users.map((u) => (
                    <tr key={u.uid}>
                      <td>
                        <div style={{ fontWeight: 700 }}>{u.displayName}</div>
                        <div style={{ fontSize: "0.75rem", color: "#64748b" }}>{u.email}</div>
                      </td>
                      <td>
                        <code style={{ color: "#1d4ed8", fontWeight: 600, fontSize: "0.78rem" }}>{u.did}</code>
                      </td>
                      <td>
                        <select
                          aria-label={`Change role for ${u.email}`}
                          className={styles.selectSmall}
                          value={u.role}
                          onChange={(e) => handleAuthorizeUser(u.uid, u.status, e.target.value)}
                          disabled={loading}
                        >
                          <option value="admin">admin (AdminOrgMSP)</option>
                          <option value="investigator">investigator (PoliceOrgMSP)</option>
                          <option value="analyst">analyst (ForensicsOrgMSP)</option>
                          <option value="judiciary">judiciary (JudiciaryOrgMSP)</option>
                          <option value="auditor">auditor (JudiciaryOrgMSP)</option>
                        </select>
                      </td>
                      <td>
                        <span
                          className={
                            u.status === "approved"
                              ? styles.badgeApproved
                              : u.status === "pending"
                              ? styles.badgePending
                              : styles.badgeRevoked
                          }
                        >
                          {u.status}
                        </span>
                      </td>
                      <td>
                        <div style={{ fontFamily: "monospace", fontSize: "0.73rem", color: "#475569" }}>
                          Key: {u.fingerprint || "ed25519"}
                        </div>
                        <div style={{ fontFamily: "monospace", fontSize: "0.7rem", color: "#94a3b8" }}>
                          Tx: {u.txHash ? u.txHash.slice(0, 18) + "..." : "genesis"}
                        </div>
                      </td>
                      <td>
                        <div className={styles.actionRow}>
                          {u.status !== "approved" && (
                            <button
                              type="button"
                              className={styles.btnApprove}
                              onClick={() => handleAuthorizeUser(u.uid, "approved")}
                              disabled={loading}
                            >
                              <UserCheck size={12} style={{ display: "inline", marginRight: "4px" }} />
                              Approve
                            </button>
                          )}
                          {u.status !== "revoked" && (
                            <button
                              type="button"
                              className={styles.btnRevoke}
                              onClick={() => handleAuthorizeUser(u.uid, "revoked")}
                              disabled={loading}
                            >
                              <UserX size={12} style={{ display: "inline", marginRight: "4px" }} />
                              Revoke
                            </button>
                          )}
                          {u.status !== "pending" && (
                            <button
                              type="button"
                              className={styles.btnSecondary}
                              onClick={() => handleAuthorizeUser(u.uid, "pending")}
                              disabled={loading}
                            >
                              Set Pending
                            </button>
                          )}
                          {u.didDocument && (
                            <button
                              type="button"
                              className={styles.btnSecondary}
                              onClick={() => {
                                setSelectedDidDoc(u.didDocument!)
                                setVerifyResult(null)
                              }}
                            >
                              Inspect W3C DID
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          {selectedDidDoc && (
            <div className={styles.sectionCard}>
              <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", marginBottom: "0.75rem" }}>
                <h3 className={styles.sectionTitle}>
                  <Key size={18} style={{ color: "#2563eb" }} />
                  <span>W3C DID v1.0 Document &amp; Ed25519 Cryptographic Verification: <code>{selectedDidDoc.id}</code></span>
                </h3>
                <div style={{ display: "flex", gap: "0.5rem" }}>
                  <button
                    type="button"
                    className={styles.btnApprove}
                    onClick={() => handleTestEd25519Verify(selectedDidDoc.id)}
                  >
                    <Play size={12} style={{ display: "inline", marginRight: "4px" }} />
                    Sign challenge with my key &amp; verify
                  </button>
                  <button
                    type="button"
                    className={styles.btnSecondary}
                    onClick={() => setSelectedDidDoc(null)}
                  >
                    Close
                  </button>
                </div>
              </div>

              {verifyResult && (
                <div
                  style={{
                    background: verifyResult.verified ? "#ecfdf5" : "#fef2f2",
                    border: `1px solid ${verifyResult.verified ? "#10b981" : "#ef4444"}`,
                    padding: "0.75rem 1rem",
                    borderRadius: "8px",
                    marginBottom: "0.85rem",
                    fontSize: "0.8rem"
                  }}
                >
                  <div>
                    <strong>Cryptographic Verification Result:</strong>{" "}
                    {verifyResult.verified ? "VALID Ed25519 Signature" : "INVALID"} — {verifyResult.reason}
                  </div>
                  {verifyResult.challenge && (
                    <div style={{ fontFamily: "monospace", marginTop: "4px", fontSize: "0.74rem", color: "#334155" }}>
                      Challenge: {verifyResult.challenge} | Signature: {verifyResult.signatureHex?.slice(0, 48)}...
                    </div>
                  )}
                </div>
              )}

              <pre className={styles.codeBlock}>{JSON.stringify(selectedDidDoc, null, 2)}</pre>
            </div>
          )}
        </>
      )}

      {/* =====================================================================
          TAB 2: OPA POLICY ENGINE (.REGO), ROLE ACCESS PARAMETERS & LOGS
         ===================================================================== */}
      {activeTab === "opa" && (
        <>
          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>
              <Play size={18} style={{ color: "#991b1b" }} />
              <span>Interactive OPA Policy Simulator (Test Server Rejection Messages)</span>
            </h2>
            <p className={styles.sectionDesc}>
              Test any combination of User Role, Authorization Status (`approved`, `pending`, `revoked`), and Action against the backend Open Policy Agent engine (`POST /api/admin/opa/evaluate`).
            </p>

            <form onSubmit={handleSimulateOpa}>
              <div className={styles.simGrid}>
                <label className={styles.simField}>
                  <span>User Role (MSP)</span>
                  <select value={simRole} onChange={(e) => setSimRole(e.target.value)}>
                    <option value="investigator">investigator (PoliceOrgMSP)</option>
                    <option value="analyst">analyst (ForensicsOrgMSP)</option>
                    <option value="judiciary">judiciary (JudiciaryOrgMSP)</option>
                    <option value="auditor">auditor (JudiciaryOrgMSP)</option>
                    <option value="admin">admin (AdminOrgMSP)</option>
                  </select>
                </label>

                <label className={styles.simField}>
                  <span>User Approval Status</span>
                  <select value={simStatus} onChange={(e) => setSimStatus(e.target.value)}>
                    <option value="approved">approved</option>
                    <option value="pending">pending (Unapproved)</option>
                    <option value="revoked">revoked (Suspended)</option>
                  </select>
                </label>

                <label className={styles.simField}>
                  <span>Requested Action</span>
                  <select value={simAction} onChange={(e) => setSimAction(e.target.value)}>
                    <option value="upload_evidence">upload_evidence (POST /api/evidence/upload)</option>
                    <option value="update_evidence_status">update_evidence_status (PATCH /api/evidence/:id/status)</option>
                    <option value="list_evidence">list_evidence (GET /api/evidence)</option>
                    <option value="inspect_evidence">inspect_evidence (GET /api/evidence/:id)</option>
                    <option value="read_audit_log">read_audit_log (GET /api/audit-log)</option>
                    <option value="approve_user">approve_user (PATCH /api/admin/users/:uid/authorize)</option>
                    <option value="revoke_user">revoke_user (PATCH /api/admin/users/:uid/authorize)</option>
                    <option value="manage_firewall">manage_firewall (POST /api/admin/firewall/reset)</option>
                  </select>
                </label>

                {simAction === "update_evidence_status" && (
                  <label className={styles.simField}>
                    <span>Target Evidence Status Parameter</span>
                    <select value={simTargetStatus} onChange={(e) => setSimTargetStatus(e.target.value)}>
                      <option value="verified">verified (Judicial Sign-Off)</option>
                      <option value="flagged">flagged (Forensic Anomaly)</option>
                      <option value="pending">pending</option>
                    </select>
                  </label>
                )}

                <button type="submit" className={styles.btnApprove} style={{ padding: "0.6rem 1rem" }}>
                  Evaluate OPA Rule on Server
                </button>
              </div>
            </form>

            {simResult && (
              <div
                style={{
                  background: simResult.allow ? "#ecfdf5" : "#fef2f2",
                  border: `2px solid ${simResult.allow ? "#10b981" : "#ef4444"}`,
                  borderRadius: "8px",
                  padding: "0.9rem 1.1rem",
                  marginTop: "0.75rem"
                }}
              >
                <div style={{ fontWeight: 700, color: simResult.allow ? "#065f46" : "#991b1b", marginBottom: "4px" }}>
                  HTTP {simResult.httpStatus} — OPA Decision: {simResult.allow ? "ALLOW" : "DENY"} (Matched Rule: <code>{simResult.rule}</code>)
                </div>
                <div style={{ fontFamily: "monospace", fontSize: "0.82rem", color: "#1e293b" }}>
                  {simResult.reason}
                </div>
              </div>
            )}
          </div>

          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>
              <ShieldAlert size={18} style={{ color: "#dc2626" }} />
              <span>Live Server Rejection &amp; OPA Decision Log ({opaData.decisionLogs.length})</span>
            </h2>
            <p className={styles.sectionDesc}>
              Every request evaluated by `opaMiddleware` is logged below with its exact input parameters and Server Rejection message.
            </p>

            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Time</th>
                    <th>Decision</th>
                    <th>OPA Rule</th>
                    <th>Caller DID &amp; Role</th>
                    <th>User Status</th>
                    <th>Action</th>
                    <th>Server Message (Reason)</th>
                  </tr>
                </thead>
                <tbody>
                  {opaData.decisionLogs.length === 0 ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: "center", color: "#64748b", padding: "1.5rem" }}>
                        No OPA decisions recorded yet. Use the simulator above or perform actions across the app.
                      </td>
                    </tr>
                  ) : (
                    opaData.decisionLogs.slice(0, 30).map((d: any) => (
                      <tr key={d.id}>
                        <td style={{ whiteSpace: "nowrap", fontSize: "0.75rem" }}>
                          {new Date(d.timestamp).toLocaleTimeString()}
                        </td>
                        <td>
                          <span className={d.allow ? styles.badgeApproved : styles.badgeRevoked}>
                            {d.allow ? "ALLOW (200)" : "DENY (403)"}
                          </span>
                        </td>
                        <td>
                          <code>{d.rule}</code>
                        </td>
                        <td>
                          <div style={{ fontFamily: "monospace", fontSize: "0.75rem" }}>{d.input?.user?.did}</div>
                          <div style={{ fontSize: "0.72rem", color: "#64748b" }}>
                            {d.input?.user?.role} ({d.input?.user?.mspId})
                          </div>
                        </td>
                        <td>
                          <span
                            className={
                              d.input?.user?.status === "approved"
                                ? styles.badgeApproved
                                : d.input?.user?.status === "pending"
                                ? styles.badgePending
                                : styles.badgeRevoked
                            }
                          >
                            {d.input?.user?.status}
                          </span>
                        </td>
                        <td>
                          <code>{d.input?.action}</code>
                        </td>
                        <td style={{ fontFamily: "monospace", fontSize: "0.76rem", color: d.allow ? "#065f46" : "#b91c1c" }}>
                          {d.reason}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>Role Access Parameters Matrix (RBAC + ABAC Logic)</h2>
            <p className={styles.sectionDesc}>
              Logic behind how roles, Hyperledger Fabric MSP IDs, user approval status, and request parameters control access.
            </p>
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Role</th>
                    <th>Fabric MSP ID</th>
                    <th>Allowed Actions</th>
                    <th>Denied Actions (Server 403)</th>
                    <th>Required Access Parameters</th>
                  </tr>
                </thead>
                <tbody>
                  {(opaData.roleAccessMatrix || []).map((row: any) => (
                    <tr key={row.role}>
                      <td>
                        <strong style={{ textTransform: "uppercase" }}>{row.role}</strong>
                        <div style={{ fontSize: "0.73rem", color: "#64748b", marginTop: "2px" }}>{row.description}</div>
                      </td>
                      <td>
                        <code>{row.mspId}</code>
                      </td>
                      <td>
                        {(row.allowedActions || []).map((a: string) => (
                          <div key={a} style={{ color: "#166534", fontSize: "0.76rem" }}>✓ {a}</div>
                        ))}
                      </td>
                      <td>
                        {!row.deniedActions || row.deniedActions.length === 0 ? (
                          <span style={{ color: "#64748b", fontSize: "0.75rem" }}>None (Full Admin)</span>
                        ) : (
                          row.deniedActions.map((a: string) => (
                            <div key={a} style={{ color: "#b91c1c", fontSize: "0.76rem" }}>✗ {a}</div>
                          ))
                        )}
                      </td>
                      <td>
                        <pre style={{ margin: 0, fontSize: "0.72rem", background: "#f8fafc", padding: "6px", borderRadius: "4px" }}>
                          {JSON.stringify(row.requiredParameters, null, 2)}
                        </pre>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </div>

          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>
              <FileCode size={18} />
              <span>Active Open Policy Agent Rego Rules (`trust-backend/policies/trust_authz.rego`)</span>
            </h2>
            <pre className={styles.codeBlock}>{opaData.regoPolicy}</pre>
          </div>
        </>
      )}

      {/* =====================================================================
          TAB 3: FIREWALL & DDOS REQUESTS MONITOR
         ===================================================================== */}
      {activeTab === "firewall" && (
        <>
          <div className={styles.sectionCard}>
            <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem", marginBottom: "1rem" }}>
              <div>
                <h2 className={styles.sectionTitle}>
                  <Flame size={18} style={{ color: "#ea580c" }} />
                  <span>Sliding-Window Firewall &amp; DDoS Rate-Limit Parameters {firewall?.parameters?.STORE ? `(state: ${firewall.parameters.STORE === "redis" ? "Redis, shared by all instances" : "in-memory, this instance"})` : ""}</span>
                </h2>
                <p className={styles.sectionDesc} style={{ marginBottom: 0 }}>
                  Enforced by `trust-backend/src/middleware/ddos.middleware.ts` at the top of the Express pipeline.
                </p>
              </div>
              <div style={{ display: "flex", gap: "0.6rem" }}>
                <button
                  type="button"
                  className={styles.btnRevoke}
                  onClick={handleSimulateFirewallBurst}
                  disabled={loading}
                >
                  <Play size={12} style={{ display: "inline", marginRight: "4px" }} />
                  Simulate 35-Request Burst (Trigger 429 Rejection)
                </button>
                <button
                  type="button"
                  className={styles.btnSecondary}
                  onClick={() => handleResetFirewall()}
                  disabled={loading}
                >
                  <Unlock size={12} style={{ display: "inline", marginRight: "4px" }} />
                  Reset Firewall &amp; Unban All IPs
                </button>
              </div>
            </div>

            <div className={styles.paramGrid}>
              <div className={styles.paramCard}>
                <div className={styles.paramName}>WINDOW_MS</div>
                <div className={styles.paramVal}>{firewall?.parameters?.WINDOW_MS ?? 10000} ms</div>
                <div className={styles.paramDesc}>10-second sliding time window per client IP address.</div>
              </div>
              <div className={styles.paramCard}>
                <div className={styles.paramName}>MAX_REQUESTS</div>
                <div className={styles.paramVal}>{firewall?.parameters?.MAX_REQUESTS ?? 30} reqs</div>
                <div className={styles.paramDesc}>Max allowed requests per 10s window. Request #31 triggers HTTP 429.</div>
              </div>
              <div className={styles.paramCard}>
                <div className={styles.paramName}>BAN_THRESHOLD</div>
                <div className={styles.paramVal}>{firewall?.parameters?.BAN_THRESHOLD ?? 50} reqs</div>
                <div className={styles.paramDesc}>Flood threshold. Request #51 locks IP in Jail.</div>
              </div>
              <div className={styles.paramCard}>
                <div className={styles.paramName}>BAN_DURATION_MS</div>
                <div className={styles.paramVal}>{firewall?.parameters?.BAN_DURATION_MS ?? 30000} ms</div>
                <div className={styles.paramDesc}>30-second mandatory cooldown for jailed flood IPs.</div>
              </div>
            </div>

            {burstResult && (
              <div className={styles.rejectionBanner} style={{ marginTop: "1rem" }}>
                <div className={styles.rejectionTitle}>
                  <AlertOctagon size={18} />
                  <span>
                    Firewall Burst Simulation Complete: {burstResult.allowedCount} Allowed (HTTP 200),{" "}
                    {burstResult.throttledCount} Rejected (HTTP 429)
                  </span>
                </div>
                {burstResult.lastBlockedPayload && (
                  <>
                    <div style={{ fontSize: "0.8rem", fontWeight: 600, marginTop: "6px" }}>
                      Exact Server HTTP 429 Rejection Payload &amp; RFC 6585 Headers:
                    </div>
                    <pre className={styles.codeBlock} style={{ marginTop: "6px" }}>
                      {JSON.stringify(
                        {
                          httpStatus: 429,
                          responseHeaders: burstResult.lastHeaders,
                          responseBody: burstResult.lastBlockedPayload
                        },
                        null,
                        2
                      )}
                    </pre>
                  </>
                )}
              </div>
            )}
          </div>

          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>Active Client IPs in Sliding Window</h2>
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Client IP</th>
                    <th>Requests in 10s Window</th>
                    <th>Remaining Quota</th>
                    <th>Firewall State</th>
                    <th>Retry-After / Jail Expiry</th>
                    <th>Action</th>
                  </tr>
                </thead>
                <tbody>
                  {(!firewall?.activeClients || firewall.activeClients.length === 0) ? (
                    <tr>
                      <td colSpan={6} style={{ textAlign: "center", color: "#64748b" }}>
                        No active IP windows currently tracked.
                      </td>
                    </tr>
                  ) : (
                    firewall.activeClients.map((c: any) => (
                      <tr key={c.ip}>
                        <td><code>{c.ip}</code></td>
                        <td><strong>{c.requestsInWindow}</strong> / {firewall?.parameters?.MAX_REQUESTS ?? 30}</td>
                        <td>{c.remainingQuota}</td>
                        <td>
                          <span
                            className={
                              c.status === "ACTIVE_OK"
                                ? styles.badgeApproved
                                : c.status === "THROTTLED_429"
                                ? styles.badgePending
                                : styles.badgeRevoked
                            }
                          >
                            {c.status}
                          </span>
                        </td>
                        <td>{c.retryAfterSeconds > 0 ? `${c.retryAfterSeconds}s` : "—"}</td>
                        <td>
                          <button
                            type="button"
                            className={styles.btnSecondary}
                            onClick={() => handleResetFirewall(c.ip)}
                          >
                            Reset / Unban IP
                          </button>
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>

          <div className={styles.sectionCard}>
            <h2 className={styles.sectionTitle}>Live Firewall Request &amp; Rejection Log</h2>
            <p className={styles.sectionDesc}>
              Real-time stream of incoming HTTP requests evaluated by `ddosMiddleware` (showing HTTP 200 Allowed vs HTTP 429 Throttled/Jailed).
            </p>
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <thead>
                  <tr>
                    <th>Timestamp</th>
                    <th>IP Address</th>
                    <th>Request</th>
                    <th>HTTP Status</th>
                    <th>Decision</th>
                    <th>Window Count</th>
                    <th>Firewall Server Message</th>
                  </tr>
                </thead>
                <tbody>
                  {(!firewall?.recentLogs || firewall.recentLogs.length === 0) ? (
                    <tr>
                      <td colSpan={7} style={{ textAlign: "center", color: "#64748b" }}>
                        No firewall requests logged yet.
                      </td>
                    </tr>
                  ) : (
                    firewall.recentLogs.slice(0, 40).map((log: any) => (
                      <tr key={log.id}>
                        <td style={{ fontSize: "0.75rem", whiteSpace: "nowrap" }}>
                          {new Date(log.timestamp).toLocaleTimeString()}
                        </td>
                        <td><code>{log.ip}</code></td>
                        <td><code>{log.method} {log.path}</code></td>
                        <td>
                          <span className={log.status === 200 ? styles.badgeApproved : styles.badgeRevoked}>
                            HTTP {log.status}
                          </span>
                        </td>
                        <td><code>{log.decision}</code></td>
                        <td>{log.requestCountInWindow}</td>
                        <td style={{ fontFamily: "monospace", fontSize: "0.75rem", color: log.status === 200 ? "#334155" : "#b91c1c" }}>
                          {log.serverMessage}
                        </td>
                      </tr>
                    ))
                  )}
                </tbody>
              </table>
            </div>
          </div>
        </>
      )}
      {activeTab === "recovery" && isAdmin && <RecoveryPanel />}
      {activeTab === "data" && isAdmin && <DataPanel />}

      {activeTab === "ledger" && (
        <div className={styles.sectionCard}>
          <div style={{ display: "flex", justifyContent: "space-between", alignItems: "center", flexWrap: "wrap", gap: "1rem", marginBottom: "1rem" }}>
            <div>
              <h2 className={styles.sectionTitle}>
                <Link2 size={18} style={{ color: "#2563eb" }} />
                <span>Ledger status &amp; database reconciliation</span>
              </h2>
              <p className={styles.sectionDesc} style={{ marginBottom: 0 }}>
                The database is a fast index; the ledger is the source of truth. Reconciliation reports any event that exists in one but not the other, or whose fields disagree.
              </p>
            </div>
            <button type="button" className={styles.btnApprove} onClick={handleReconcile} disabled={loading}>
              <RefreshCw size={12} style={{ display: "inline", marginRight: 4 }} /> Run reconciliation now
            </button>
          </div>

          {ledger && (
            <div className={styles.tableWrapper}>
              <table className={styles.table}>
                <tbody>
                  <tr><td>Ledger mode</td><td><code>{ledger.ledger?.mode}</code>{ledger.ledger?.mode === "local" ? " (hash-chained file; set LEDGER_MODE=fabric for a Fabric network)" : ""}</td></tr>
                  <tr><td>Channel / chaincode</td><td><code>{ledger.ledger?.channel} / {ledger.ledger?.chaincode}</code></td></tr>
                  <tr><td>Gateway MSP</td><td><code>{ledger.ledger?.mspId}</code></td></tr>
                  {ledger.ledger?.height !== undefined && <tr><td>Height</td><td>{ledger.ledger.height} blocks</td></tr>}
                  {ledger.chain && (
                    <tr><td>Hash chain</td><td style={{ color: ledger.chain.ok ? "#059669" : "#dc2626", fontWeight: 700 }}>
                      {ledger.chain.ok ? `intact (${ledger.chain.checkedBlocks} blocks recomputed)` : `BROKEN at block ${ledger.chain.firstBadBlock}: ${ledger.chain.reason}`}
                    </td></tr>
                  )}
                  <tr><td>Database</td><td><code>{ledger.database}</code></td></tr>
                </tbody>
              </table>
            </div>
          )}

          {reconcile && (
            <div style={{ marginTop: "1rem" }}>
              <div style={{ fontWeight: 700, color: reconcile.ok ? "#059669" : "#dc2626", marginBottom: "0.5rem" }}>
                {reconcile.ok ? "Database and ledger agree" : `${reconcile.issues.length} issue(s) found`}{" "}
                <span style={{ fontWeight: 400, color: "#64748b", fontSize: "0.8rem" }}>
                  — {new Date(reconcile.ranAt).toLocaleString()}, {reconcile.counts.dbAudit} DB / {reconcile.counts.ledgerAudit} ledger audit events,
                  {" "}{reconcile.counts.dbEvidence} DB / {reconcile.counts.ledgerEvidence} ledger evidence records
                </span>
              </div>
              {reconcile.error && <p style={{ color: "#dc2626", fontFamily: "monospace" }}>{reconcile.error}</p>}
              {reconcile.issues.length > 0 && (
                <div className={styles.tableWrapper}>
                  <table className={styles.table}>
                    <thead><tr><th>Kind</th><th>ID</th><th>Detail</th></tr></thead>
                    <tbody>
                      {reconcile.issues.map((i: any) => (
                        <tr key={i.kind + i.id}><td><code>{i.kind}</code></td><td><code>{i.id}</code></td><td style={{ fontSize: "0.8rem" }}>{i.detail}</td></tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  )
}

export default function AdminPage() {
  return (
    <ProtectedRoute roles={["admin", "auditor"]}>
      <AdminDashboardContent />
    </ProtectedRoute>
  )
}

