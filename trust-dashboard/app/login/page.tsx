"use client"

import React, { useEffect, useRef, useState } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useAuth, KeyMissingError, firebaseConfigured, InternalUser } from "@/context/AuthContext"
import { parseKeyFile } from "@/lib/didKeys"
import { ShieldCheck, Mail, Lock, AlertCircle, LogIn, KeyRound, Upload, UserCheck } from "lucide-react"
import styles from "./login.module.css"

interface DemoEntry { key: string; email: string; role: string; status: string; did: string }

const DEMO_MODE = process.env.NEXT_PUBLIC_DEMO_MODE === "true"

export default function LoginPage() {
  const [email, setEmail] = useState("")
  const [password, setPassword] = useState("")
  const [error, setError] = useState("")
  const [loading, setLoading] = useState(false)
  const [needsKeyFor, setNeedsKeyFor] = useState<string | null>(null)
  const [demo, setDemo] = useState<DemoEntry[]>([])
  const fileInput = useRef<HTMLInputElement>(null)

  const { signInWithEmail, signInWithGoogle, signInWithKeyFile, importKeyFile, requestRecovery } = useAuth()
  const [recovering, setRecovering] = useState(false)
  const [reason, setReason] = useState("")
  const [recoveryResult, setRecoveryResult] = useState<string | null>(null)

  const submitRecovery = async (e: React.FormEvent) => {
    e.preventDefault()
    setError("")
    setLoading(true)
    try {
      const r = await requestRecovery(email, firebaseConfigured ? password : undefined, reason)
      setRecoveryResult(
        `Request filed. Your new key file was downloaded (new DID ${r.newDid}). ${r.requiredApprovals} administrator approval(s) are needed` +
        `${r.reducedQuorum ? " (fewer administrators exist than the configured quorum)" : ""}; contact them to confirm your identity. ` +
        `The request expires ${new Date(r.expiresAt).toLocaleString()}. After approval, sign in normally.`
      )
    } catch (err) {
      setError((err as Error).message || "Recovery request failed")
    } finally {
      setLoading(false)
    }
  }
  const router = useRouter()

  useEffect(() => {
    if (!DEMO_MODE) return
    fetch("/demo-keys/index.json")
      .then(r => (r.ok ? r.json() : []))
      .then(setDemo)
      .catch(() => setDemo([]))
  }, [])

  const goHome = (u: InternalUser) => router.push(u.role === "admin" && u.status === "approved" ? "/admin" : "/dashboard")

  const run = async (fn: () => Promise<InternalUser>) => {
    setError("")
    setLoading(true)
    try {
      goHome(await fn())
    } catch (caught) {
      const err = caught as Error & { code?: string }
      if (err instanceof KeyMissingError) {
        setNeedsKeyFor(err.did)
        setError(err.message)
      } else if (err?.code === "NOT_REGISTERED") {
        setError("No TRUST identity is registered for that email. Register first.")
      } else {
        setError(err?.message || "Sign-in failed")
      }
    } finally {
      setLoading(false)
    }
  }

  const handleKeyFile = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0]
    e.target.value = ""
    if (!file) return
    await run(async () => {
      const key = await importKeyFile(file)
      if (needsKeyFor && key.did !== needsKeyFor) throw new Error(`That key file is for ${key.did}, not ${needsKeyFor}`)
      setNeedsKeyFor(null)
      if (key.email) setEmail(key.email)
      // With Firebase on, if this key matches the email input and a password was typed, complete with password
      if (firebaseConfigured && email && key.email && email.toLowerCase() === key.email.toLowerCase() && password) {
        return signInWithEmail(email, password)
      }
      return signInWithKeyFile(key)
    })
  }

  const demoLogin = (entry: DemoEntry) =>
    run(async () => {
      const res = await fetch(`/demo-keys/${entry.key}.trustkey.json`)
      if (!res.ok) throw new Error("Demo key file not found. Run `npm run seed:demo -- --public` in trust-backend.")
      const key = parseKeyFile(await res.text())
      return signInWithKeyFile(await importKeyFile(JSON.stringify(key)))
    })

  return (
    <div className={styles.container}>
      <div className={styles.card}>
        <div className={styles.header}>
          <div className={styles.logoBadge}>
            <ShieldCheck size={16} />
            <span>W3C DID CHALLENGE-RESPONSE</span>
          </div>
          <h1 className={styles.title}>Agency Authentication</h1>
          <p className={styles.subtitle}>
            {firebaseConfigured
              ? "Firebase password, then a signature from the DID key held in this browser"
              : "Signed in with the Ed25519 DID key held in this browser"}
          </p>
        </div>

        {error && (
          <div className={styles.errorBanner}>
            <AlertCircle size={16} />
            <span>{error}</span>
          </div>
        )}

        <form onSubmit={e => { e.preventDefault(); run(() => signInWithEmail(email, firebaseConfigured ? password : undefined)) }} className={styles.form}>
          <div className={styles.inputGroup}>
            <label htmlFor="email">Official Agency Email</label>
            <div className={styles.inputWrapper}>
              <Mail className={styles.inputIcon} size={18} />
              <input id="email" type="email" required placeholder="officer@agency.gov" value={email} onChange={e => setEmail(e.target.value)} className={styles.input} />
            </div>
          </div>

          {firebaseConfigured && (
            <div className={styles.inputGroup}>
              <label htmlFor="password">Password</label>
              <div className={styles.inputWrapper}>
                <Lock className={styles.inputIcon} size={18} />
                <input id="password" type="password" required placeholder="••••••••••••" value={password} onChange={e => setPassword(e.target.value)} className={styles.input} />
              </div>
            </div>
          )}

          <button type="submit" className={styles.submitBtn} disabled={loading}>
            {loading ? "Signing challenge..." : <>Sign In <LogIn size={18} /></>}
          </button>
        </form>

        <div style={{ marginTop: "0.75rem", display: "flex", flexDirection: "column", gap: "0.5rem" }}>
          {firebaseConfigured && (
            <button type="button" onClick={() => run(signInWithGoogle)} className={styles.googleBtn} disabled={loading}>
              <KeyRound size={16} />
              <span>Continue with Google</span>
            </button>
          )}
          <button type="button" onClick={() => fileInput.current?.click()} className={styles.googleBtn} disabled={loading}>
            <Upload size={16} />
            <span>{needsKeyFor ? "Import your key file to continue" : "Sign in with a key file (.trustkey.json)"}</span>
          </button>
          <input ref={fileInput} type="file" accept=".json,application/json" hidden onChange={handleKeyFile} />
        </div>

        <p className={styles.footerText} style={{ marginTop: "0.75rem" }}>
          <button type="button" onClick={() => { setRecovering(!recovering); setRecoveryResult(null) }}
            style={{ background: "none", border: 0, color: "#f87171", textDecoration: "underline", cursor: "pointer", fontSize: "inherit" }}>
            Lost your key file?
          </button>
        </p>

        {recovering && (
          <form onSubmit={submitRecovery} className={styles.form} style={{ marginTop: "0.5rem" }}>
            <p className={styles.footerText} style={{ textAlign: "left", margin: 0 }}>
              A new key is generated in this browser. Your DID switches to it only after two different administrators approve,
              so nobody can take over your identity alone. Evidence you signed before stays verifiable.
            </p>
            <div className={styles.inputGroup}>
              <label htmlFor="reason">What happened? (enter your email above{firebaseConfigured ? " and password" : ""})</label>
              <input id="reason" className={styles.input} style={{ paddingLeft: "1rem" }} required placeholder="e.g. laptop replaced, browser data cleared" value={reason} onChange={e => setReason(e.target.value)} />
            </div>
            <button type="submit" className={styles.submitBtn} disabled={loading || !email}>Request key recovery</button>
            {recoveryResult && <p className={styles.footerText} style={{ textAlign: "left", color: "#a7f3d0" }}>{recoveryResult}</p>}
          </form>
        )}

        <p className={styles.footerText} style={{ marginTop: "1rem" }}>
          New agency officer?{" "}
          <Link href="/signup" style={{ color: "#f87171", fontWeight: 600, textDecoration: "underline" }}>
            Register &amp; generate your DID
          </Link>
        </p>

        {DEMO_MODE && demo.length > 0 && (
          <>
            <div className={styles.divider}>
              <span>DEMO ACCOUNTS (NEXT_PUBLIC_DEMO_MODE)</span>
            </div>
            <div className={styles.roleSwitcherSection}>
              <p className={styles.roleSwitcherTitle}>Uses seeded key files; real sign-in, real signatures</p>
              <div className={styles.roleBtnGrid}>
                {demo.map(d => (
                  <button key={d.key} type="button" className={styles.roleQuickBtn} onClick={() => demoLogin(d)} disabled={loading}>
                    <div className={styles.roleBtnLeft}>
                      <UserCheck size={16} style={{ color: d.status === "approved" ? "#34d399" : d.status === "pending" ? "#fbbf24" : "#ef4444" }} />
                      <span>{d.email}</span>
                    </div>
                    <span className={styles.roleBtnBadge}>{d.role} · {d.status}</span>
                  </button>
                ))}
              </div>
            </div>
          </>
        )}
      </div>
    </div>
  )
}
