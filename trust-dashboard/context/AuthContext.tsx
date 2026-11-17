"use client"

import React, { createContext, useCallback, useContext, useEffect, useRef, useState } from "react"
import {
  createUserWithEmailAndPassword,
  signInWithEmailAndPassword,
  signInWithPopup,
  signOut,
  updateProfile,
  User as FirebaseUser
} from "firebase/auth"
import { auth, googleProvider } from "@/lib/firebase"
import { DIDDocument } from "@/types"
import {
  DidKeyFile,
  generateKeyPair,
  loadKey,
  parseKeyFile,
  saveKey,
  signWithKey,
  downloadKeyFile
} from "@/lib/didKeys"

export type Role = "admin" | "investigator" | "analyst" | "judiciary" | "auditor"

export interface InternalUser {
  uid: string
  email: string
  displayName: string
  role: Role
  requestedRole?: string | null
  did: string
  mspId: string
  status: "approved" | "pending" | "revoked"
  authProvider?: "firebase" | "key"
  publicKeyHex?: string
  fingerprint?: string
  didDocument?: DIDDocument
  txHash?: string | null
}

/** Thrown when the browser does not hold the private key for the account being signed into. */
export class KeyMissingError extends Error {
  constructor(public did: string, public email: string) {
    super(`This browser does not hold the private key for ${did}. Import your .trustkey.json file to continue.`)
    this.name = "KeyMissingError"
  }
}

export const API_URL = process.env.NEXT_PUBLIC_API_URL || "http://localhost:3001"
export const firebaseConfigured = !!auth

interface Session {
  token: string
  expiresAt: string
  user: InternalUser
}

export interface AuthContextType {
  user: InternalUser | null
  loading: boolean
  role: string
  did: string
  mspId: string
  status: "approved" | "pending" | "revoked"
  sessionExpiresAt: string | null
  /** Email (+ password when Firebase is configured) then DID challenge-response. */
  signInWithEmail: (email: string, password?: string) => Promise<InternalUser>
  signInWithGoogle: (roleOverride?: string) => Promise<InternalUser>
  /** Sign in with a key file only (accounts registered without Firebase, e.g. demo accounts). */
  signInWithKeyFile: (key: DidKeyFile) => Promise<InternalUser>
  importKeyFile: (file: File | string) => Promise<DidKeyFile>
  signUpWithEmail: (email: string, password: string, name: string, requestedRole: string) => Promise<{ user: InternalUser; key: DidKeyFile }>
  logout: () => Promise<void>
  /** Returns the current session JWT (name kept for existing callers). */
  getIdToken: () => Promise<string | null>
  /** fetch() against the API with the session token; signs the user out on 401. */
  authFetch: (path: string, init?: RequestInit) => Promise<Response>
  /** Signs a payload with the current user's DID key (held only in this browser). */
  signPayload: (payload: string) => string
  hasKey: boolean
  refreshUserStatus: () => Promise<void>
  /** Lost key: generate a new key here and ask administrators to rotate the DID to it. */
  requestRecovery: (email: string, password: string | undefined, reason: string) => Promise<{ newDid: string; requiredApprovals: number; reducedQuorum: boolean; expiresAt: string }>
}

const AuthContext = createContext<AuthContextType | undefined>(undefined)
const SESSION_KEY = "trust_session"

async function postJson(path: string, body: unknown) {
  const res = await fetch(`${API_URL}${path}`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body)
  })
  const json = await res.json().catch(() => ({}))
  if (!res.ok) {
    throw Object.assign(new Error(json.error || `Request failed (${res.status})`), { code: json.code as string | undefined, status: res.status })
  }
  return json.data
}

export function AuthProvider({ children }: { children: React.ReactNode }) {
  const [session, setSession] = useState<Session | null>(null)
  const [loading, setLoading] = useState(true)
  const expiryTimer = useRef<ReturnType<typeof setTimeout> | null>(null)

  const persist = useCallback((s: Session | null) => {
    setSession(s)
    try {
      if (s) sessionStorage.setItem(SESSION_KEY, JSON.stringify(s))
      else sessionStorage.removeItem(SESSION_KEY)
    } catch {
      // storage unavailable (private mode); session lives in memory only
    }
  }, [])

  // Restore a still-valid session on reload
  useEffect(() => {
    try {
      const raw = sessionStorage.getItem(SESSION_KEY)
      if (raw) {
        const s: Session = JSON.parse(raw)
        // Restoring from sessionStorage must happen after hydration (it is unavailable during prerender).
        // eslint-disable-next-line react-hooks/set-state-in-effect
        if (new Date(s.expiresAt).getTime() > Date.now() + 5000) setSession(s)
        else sessionStorage.removeItem(SESSION_KEY)
      }
    } catch {
      // ignore
    }
    setLoading(false)
  }, [])

  const logout = useCallback(async () => {
    try {
      if (auth) await signOut(auth)
    } catch {
      // ignore
    }
    persist(null)
  }, [persist])

  // Sign out automatically when the session token expires
  useEffect(() => {
    if (expiryTimer.current) clearTimeout(expiryTimer.current)
    if (!session) return
    const ms = new Date(session.expiresAt).getTime() - Date.now()
    expiryTimer.current = setTimeout(() => logout(), Math.max(ms, 0))
    return () => {
      if (expiryTimer.current) clearTimeout(expiryTimer.current)
    }
  }, [session, logout])

  // Approval status lives in the registry, not in the token: re-read the profile whenever a
  // session starts or the page reloads, so an approval or revocation shows up without signing in again.
  const token = session?.token
  useEffect(() => {
    if (!token) return
    let cancelled = false
    fetch(`${API_URL}/api/users/me`, { headers: { Authorization: `Bearer ${token}` } })
      .then(r => (r.ok ? r.json() : null))
      .then(json => {
        if (!cancelled && json?.data) setSession(prev => (prev && prev.token === token ? { ...prev, user: json.data } : prev))
      })
      .catch(() => undefined)
    return () => {
      cancelled = true
    }
  }, [token])

  /** Challenge-response with the DID key held in this browser. */
  const completeDidLogin = useCallback(
    async (lookup: { email?: string; did?: string }, firebaseUser?: FirebaseUser | null, keyOverride?: DidKeyFile): Promise<InternalUser> => {
      const challenge = await postJson("/api/auth/challenge", lookup)
      const key = keyOverride && keyOverride.did === challenge.did ? keyOverride : loadKey(challenge.did)
      if (!key) throw new KeyMissingError(challenge.did, lookup.email || "")
      if (keyOverride && keyOverride.did !== challenge.did) throw new Error("That key file belongs to a different identity")

      const firebaseIdToken = firebaseUser ? await firebaseUser.getIdToken() : undefined
      if (challenge.firebaseRequired && !firebaseIdToken) {
        throw new Error("This account was registered with Firebase: sign in with your password or Google as well as your key")
      }
      const data = await postJson("/api/auth/verify", {
        did: challenge.did,
        nonce: challenge.nonce,
        signatureHex: signWithKey(key, challenge.payload),
        firebaseIdToken
      })
      saveKey(key)
      const s: Session = { token: data.token, expiresAt: data.expiresAt, user: data.user }
      persist(s)
      return data.user
    },
    [persist]
  )

  const signInWithEmail = async (email: string, password?: string) => {
    const normalized = email.trim().toLowerCase()
    let fbUser: FirebaseUser | null = null
    if (auth && password) {
      const cred = await signInWithEmailAndPassword(auth, normalized, password)
      fbUser = cred.user
    }
    return completeDidLogin({ email: normalized }, fbUser)
  }

  const signInWithGoogle = async (roleOverride?: string) => {
    if (!auth) throw new Error("Google sign-in needs Firebase to be configured (NEXT_PUBLIC_FIREBASE_*)")
    const cred = await signInWithPopup(auth, googleProvider)
    if (!cred.user.email) throw new Error("Google account has no email")
    const email = cred.user.email.toLowerCase()
    try {
      return await completeDidLogin({ email }, cred.user)
    } catch (err: any) {
      if (err?.code === "NOT_REGISTERED" || err?.message?.includes("not found")) {
        const isAdmin = email === "aditi.kamath@somaiya.edu"
        const requestedRole = isAdmin ? "admin" : (roleOverride || "investigator")
        const kp = generateKeyPair()
        const registered: InternalUser = await postJson("/api/users/register", {
          email,
          displayName: cred.user.displayName || email.split("@")[0],
          requestedRole,
          publicKeyHex: kp.publicKeyHex,
          firebaseIdToken: await cred.user.getIdToken()
        })
        const key: DidKeyFile = {
          format: "trust-did-key/1",
          did: registered.did,
          email,
          publicKeyHex: kp.publicKeyHex,
          secretKeyHex: kp.secretKeyHex,
          createdAt: new Date().toISOString()
        }
        saveKey(key)
        downloadKeyFile(key)
        return await completeDidLogin({ did: registered.did }, cred.user, key)
      }
      throw err
    }
  }

  const signInWithKeyFile = async (key: DidKeyFile) => {
    let fbUser = auth?.currentUser || null
    if (fbUser && key.email && fbUser.email?.toLowerCase() !== key.email.toLowerCase()) {
      if (auth) await signOut(auth).catch(() => undefined)
      fbUser = null
    }
    return completeDidLogin({ did: key.did }, fbUser, key)
  }

  const importKeyFile = async (file: File | string) => {
    const text = typeof file === "string" ? file : await file.text()
    const key = parseKeyFile(text)
    saveKey(key)
    return key
  }

  const signUpWithEmail = async (email: string, password: string, name: string, requestedRole: string) => {
    const normalized = email.trim().toLowerCase()
    let fbUser: FirebaseUser | null = null
    if (auth) {
      try {
        const cred = await createUserWithEmailAndPassword(auth, normalized, password)
        if (name) await updateProfile(cred.user, { displayName: name })
        fbUser = cred.user
      } catch (fbErr: any) {
        if (fbErr?.code === "auth/email-already-in-use") {
          try {
            const cred = await signInWithEmailAndPassword(auth, normalized, password)
            if (name && !cred.user.displayName) await updateProfile(cred.user, { displayName: name })
            fbUser = cred.user
          } catch (signInErr: any) {
            if (signInErr?.code === "auth/wrong-password" || signInErr?.code === "auth/invalid-credential") {
              throw new Error("This email is already registered in Firebase with a different password. Please enter the existing password, or sign in directly.")
            }
            throw fbErr
          }
        } else {
          throw fbErr
        }
      }
    }
    // Keys are generated here; only the public key leaves the browser.
    const kp = generateKeyPair()
    const registered: InternalUser = await postJson("/api/users/register", {
      email: normalized,
      displayName: name,
      requestedRole,
      publicKeyHex: kp.publicKeyHex,
      firebaseIdToken: fbUser ? await fbUser.getIdToken() : undefined
    })
    const key: DidKeyFile = {
      format: "trust-did-key/1",
      did: registered.did,
      email: normalized,
      publicKeyHex: kp.publicKeyHex,
      secretKeyHex: kp.secretKeyHex,
      createdAt: new Date().toISOString()
    }
    saveKey(key)
    downloadKeyFile(key)
    const user = await completeDidLogin({ did: registered.did }, fbUser, key)
    return { user, key }
  }

  const requestRecovery = async (email: string, password: string | undefined, reason: string) => {
    const normalized = email.trim().toLowerCase()
    let firebaseIdToken: string | undefined
    if (auth && password) {
      const cred = await signInWithEmailAndPassword(auth, normalized, password)
      firebaseIdToken = await cred.user.getIdToken()
    }
    const kp = generateKeyPair()
    const data = await postJson("/api/recovery/request", { email: normalized, newPublicKeyHex: kp.publicKeyHex, reason, firebaseIdToken })
    const key: DidKeyFile = {
      format: "trust-did-key/1",
      did: data.newDid,
      email: normalized,
      publicKeyHex: kp.publicKeyHex,
      secretKeyHex: kp.secretKeyHex,
      createdAt: new Date().toISOString()
    }
    // The new key only works after the administrators approve; keep it now so it is not lost.
    saveKey(key)
    downloadKeyFile(key)
    return data
  }

  const getIdToken = async () => session?.token ?? null

  const authFetch = useCallback(
    async (path: string, init: RequestInit = {}) => {
      const headers = new Headers(init.headers)
      if (session?.token) headers.set("Authorization", `Bearer ${session.token}`)
      const res = await fetch(path.startsWith("http") ? path : `${API_URL}${path}`, { ...init, headers })
      if (res.status === 401) await logout()
      return res
    },
    [session, logout]
  )

  const signPayload = (payload: string) => {
    if (!session) throw new Error("Not signed in")
    const key = loadKey(session.user.did)
    if (!key) throw new KeyMissingError(session.user.did, session.user.email)
    return signWithKey(key, payload)
  }

  const refreshUserStatus = async () => {
    if (!session) return
    const res = await authFetch("/api/users/me")
    if (res.ok) {
      const json = await res.json()
      persist({ ...session, user: json.data })
    }
  }

  const user = session?.user ?? null
  const hasKey = typeof window !== "undefined" && !!user && !!loadKey(user.did)

  return (
    <AuthContext.Provider
      value={{
        user,
        loading,
        role: user?.role || "",
        did: user?.did || "",
        mspId: user?.mspId || "",
        status: user?.status || "pending",
        sessionExpiresAt: session?.expiresAt || null,
        signInWithEmail,
        signInWithGoogle,
        signInWithKeyFile,
        importKeyFile,
        signUpWithEmail,
        logout,
        getIdToken,
        authFetch,
        signPayload,
        hasKey,
        refreshUserStatus,
        requestRecovery
      }}
    >
      {children}
    </AuthContext.Provider>
  )
}

export function useAuth() {
  const context = useContext(AuthContext)
  if (context === undefined) throw new Error("useAuth must be used within an AuthProvider")
  return context
}
