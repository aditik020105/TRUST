"use client"

import React, { useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useAuth, InternalUser, firebaseConfigured } from "@/context/AuthContext"
import { DidKeyFile, downloadKeyFile } from "@/lib/didKeys"
import {
  ShieldCheck,
  User,
  Mail,
  Lock,
  Briefcase,
  AlertCircle,
  CheckCircle,
  Key,
  ArrowRight
} from "lucide-react"
import styles from "../login/login.module.css"

export default function SignupPage() {
  const [name, setName] = useState("")
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [role, setRole] = useState("investigator")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [createdUser, setCreatedUser] = useState<InternalUser | null>(null)
  const [keyFile, setKeyFile] = useState<DidKeyFile | null>(null)

  const router = useRouter()
  const { signUpWithEmail } = useAuth()

  const handleSignup = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)

    try {
      const { user, key } = await signUpWithEmail(email, password, name, role)
      setCreatedUser(user)
      setKeyFile(key)
    } catch (err: any) {
      setError(err.message || "Failed to register user account.")
    } finally {
      setLoading(false)
    }
  }

  return (
    <div className={styles.container}>
      <div className={styles.card} style={{ maxWidth: createdUser ? "640px" : "460px" }}>
        <div className={styles.header}>
          <div className={styles.logoBadge}>
            <ShieldCheck size={16} />
            <span>W3C DID + FIREBASE REGISTRATION</span>
          </div>
          <h1 className={styles.title}>
            {createdUser ? "W3C DID Provisioned" : "Register Agency Identity"}
          </h1>
          <p className={styles.subtitle}>
            {createdUser
              ? "Your Ed25519 key was generated in this browser; only the public key was sent to the server."
              : firebaseConfigured
              ? "Creates a Firebase login, then an Ed25519 key in this browser for your W3C DID"
              : "Generates an Ed25519 key in this browser and registers your W3C DID"}
          </p>
        </div>

        {error && (
          <div className={styles.errorBanner}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        {createdUser ? (
          <div style={{ display: "flex", flexDirection: "column", gap: "1rem", color: "#e2e8f0" }}>
            <div
              style={{
                background: createdUser.status === "pending" ? "rgba(245, 158, 11, 0.15)" : "rgba(16, 185, 129, 0.15)",
                border: `1px solid ${createdUser.status === "pending" ? "rgba(245, 158, 11, 0.4)" : "rgba(16, 185, 129, 0.4)"}`,
                padding: "0.85rem 1rem",
                borderRadius: "8px",
                fontSize: "0.85rem"
              }}
            >
              <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 700, marginBottom: "4px" }}>
                <CheckCircle size={16} />
                <span>
                  Authorization Status: {String(createdUser.status || "pending").toUpperCase()}
                </span>
              </div>
              {createdUser.status === "pending" ? (
                <p style={{ margin: 0, color: "#fde68a", fontSize: "0.8rem" }}>
                  Your account is currently <strong>PENDING</strong> Administrator approval. If you try to access or upload evidence now, the server&apos;s OPA policy engine (`user_must_be_approved`) will reject the request with HTTP 403 until an Admin approves your DID in the Admin Dashboard.
                </p>
              ) : (
                <p style={{ margin: 0, color: "#a7f3d0", fontSize: "0.8rem" }}>
                  Your account is <strong>APPROVED</strong> and ready to interact with the Hyperledger Fabric chain of custody.
                </p>
              )}
            </div>

            {keyFile && (
              <div style={{ background: "rgba(239, 68, 68, 0.12)", border: "1px solid rgba(239, 68, 68, 0.45)", padding: "0.85rem 1rem", borderRadius: "8px", fontSize: "0.8rem" }}>
                <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontWeight: 700, marginBottom: "4px" }}>
                  <Key size={16} />
                  <span>Keep your key file safe</span>
                </div>
                <p style={{ margin: "0 0 0.5rem", color: "#fecaca" }}>
                  <code>{keyFile.email}.trustkey.json</code> was downloaded. It holds your private key, which never left this browser.
                  You need it to sign in on another browser. If you lose it, an administrator must revoke this DID and you register again.
                </p>
                <button type="button" className={styles.googleBtn} onClick={() => downloadKeyFile(keyFile)}>
                  <Key size={14} /> <span>Download key file again</span>
                </button>
              </div>
            )}

            <div
              style={{
                background: "rgba(15, 23, 42, 0.75)",
                border: "1px solid rgba(255,255,255,0.12)",
                borderRadius: "8px",
                padding: "1rem",
                fontSize: "0.8rem",
                display: "flex",
                flexDirection: "column",
                gap: "0.5rem"
              }}
            >
              <div><strong>W3C DID:</strong> <code style={{ color: "#60a5fa" }}>{createdUser.did}</code></div>
              <div><strong>Role &amp; Organization MSP:</strong> <code>{createdUser.role} ({createdUser.mspId})</code></div>
              <div><strong>Ed25519 Key Fingerprint:</strong> <code style={{ color: "#a78bfa" }}>{createdUser.fingerprint || "Generated"}</code></div>
              {createdUser.didDocument && (
                <details style={{ marginTop: "0.4rem" }}>
                  <summary style={{ cursor: "pointer", color: "#94a3b8", fontWeight: 600 }}>
                    Inspect Generated W3C DID v1.0 Document (JSON)
                  </summary>
                  <pre
                    style={{
                      marginTop: "0.5rem",
                      padding: "0.75rem",
                      background: "#020617",
                      borderRadius: "6px",
                      overflowX: "auto",
                      fontSize: "0.72rem",
                      color: "#38bdf8"
                    }}
                  >
                    {JSON.stringify(createdUser.didDocument, null, 2)}
                  </pre>
                </details>
              )}
            </div>

            <div style={{ display: "flex", gap: "0.75rem", marginTop: "0.5rem" }}>
              <Link href="/dashboard" className={styles.submitBtn} style={{ textDecoration: "none", flex: 1 }}>
                <span>Go to Dashboard</span>
                <ArrowRight size={16} />
              </Link>
            </div>
          </div>
        ) : (
          <form onSubmit={handleSignup} className={styles.form}>
            <div className={styles.inputGroup}>
              <label htmlFor="name">Full Name &amp; Rank</label>
              <div className={styles.inputWrapper}>
                <User className={styles.inputIcon} size={18} />
                <input
                  id="name"
                  type="text"
                  required
                  placeholder="Inspector Priya Nair"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  className={styles.input}
                />
              </div>
            </div>

            <div className={styles.inputGroup}>
              <label htmlFor="email">Agency Email</label>
              <div className={styles.inputWrapper}>
                <Mail className={styles.inputIcon} size={18} />
                <input
                  id="email"
                  type="email"
                  required
                  placeholder="priya.nair@trust.gov"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  className={styles.input}
                />
              </div>
            </div>

            {firebaseConfigured && (
            <div className={styles.inputGroup}>
              <label htmlFor="password">Password (min 6 characters)</label>
              <div className={styles.inputWrapper}>
                <Lock className={styles.inputIcon} size={18} />
                <input
                  id="password"
                  type="password"
                  required
                  minLength={6}
                  placeholder="••••••••••••"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  className={styles.input}
                />
              </div>
            </div>
            )}

            <div className={styles.inputGroup}>
              <label htmlFor="role">Requested Role (an admin confirms it on approval)</label>
              <div className={styles.inputWrapper}>
                <Briefcase className={styles.inputIcon} size={18} />
                <select
                  id="role"
                  value={role}
                  onChange={(e) => setRole(e.target.value)}
                  className={styles.input}
                >
                  <option value="investigator">Investigator — PoliceOrgMSP (Upload &amp; View)</option>
                  <option value="analyst">Forensic Analyst — ForensicsOrgMSP (Inspect &amp; Flag)</option>
                  <option value="judiciary">Judicial Authority — JudiciaryOrgMSP (Verify &amp; Sign-off)</option>
                  <option value="auditor">Compliance Auditor — JudiciaryOrgMSP (Read-Only)</option>
                </select>
              </div>
            </div>

            <p className={styles.footerText} style={{ textAlign: "left", margin: 0 }}>
              New accounts start as <strong>pending</strong>. An administrator approves you and confirms your role;
              until then the policy engine rejects every action.
            </p>

            <button type="submit" className={styles.submitBtn} disabled={loading}>
              {loading ? "Generating Ed25519 Keypair & W3C DID..." : "Register & Generate W3C DID"}
            </button>

            <p className={styles.footerText}>
              Already registered?{" "}
              <Link href="/login" style={{ color: "#f87171", fontWeight: 600, textDecoration: "underline" }}>
                Sign In Here
              </Link>
            </p>
          </form>
        )}
      </div>
    </div>
  )
}

