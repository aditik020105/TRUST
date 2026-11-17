import crypto from "crypto"
import jwt from "jsonwebtoken"
import { UserRecord } from "./user.service"

/**
 * Session tokens and login challenges.
 *
 * Login = (optional) Firebase ID token + a signature over a one-time server nonce made
 * with the private key behind the user's DID. On success the backend issues its own
 * HS256 session JWT that expires after SESSION_TTL_MINUTES. Role and status are NOT
 * trusted from the token; the auth middleware re-reads them from the registry.
 */

const DEFAULT_SECRET = "trust-secret-key-change-in-production"
const ISSUER = "trust-backend"
const AUDIENCE = "trust-dashboard"
const CHALLENGE_TTL_MS = 2 * 60 * 1000

function secret(): string {
  const s = process.env.JWT_SECRET
  if (!s || s === DEFAULT_SECRET) {
    if (process.env.NODE_ENV === "production") {
      throw new Error("JWT_SECRET must be set to a long random value in production")
    }
    return s || DEFAULT_SECRET
  }
  return s
}

export function sessionTtlMinutes(): number {
  const n = Number(process.env.SESSION_TTL_MINUTES || 60)
  return Number.isFinite(n) && n > 0 ? Math.min(n, 24 * 60) : 60
}

export interface SessionClaims {
  sub: string
  did: string
  email: string
  role: string
  mspId: string
  iat: number
  exp: number
  jti: string
}

export function issueSessionToken(user: Pick<UserRecord, "uid" | "did" | "email" | "role" | "mspId">): { token: string; expiresAt: string } {
  const ttl = sessionTtlMinutes()
  const token = jwt.sign(
    { did: user.did, email: user.email, role: user.role, mspId: user.mspId },
    secret(),
    { algorithm: "HS256", subject: user.uid, expiresIn: ttl * 60, issuer: ISSUER, audience: AUDIENCE, jwtid: crypto.randomUUID() }
  )
  return { token, expiresAt: new Date(Date.now() + ttl * 60 * 1000).toISOString() }
}

export function verifySessionToken(token: string): SessionClaims {
  return jwt.verify(token, secret(), { algorithms: ["HS256"], issuer: ISSUER, audience: AUDIENCE }) as SessionClaims
}

// ---------------------------------------------------------------------------
// One-time login challenges (in memory; a challenge lives for 2 minutes and is
// deleted on first use, so a captured signature cannot be replayed).
// ---------------------------------------------------------------------------
const challenges = new Map<string, { did: string; expires: number }>()

export function createChallenge(did: string): { nonce: string; expiresAt: string } {
  const now = Date.now()
  for (const [k, v] of challenges) if (v.expires < now) challenges.delete(k)
  const nonce = crypto.randomBytes(32).toString("hex")
  challenges.set(nonce, { did, expires: now + CHALLENGE_TTL_MS })
  return { nonce, expiresAt: new Date(now + CHALLENGE_TTL_MS).toISOString() }
}

export function consumeChallenge(nonce: string, did: string): boolean {
  const c = challenges.get(nonce)
  if (!c) return false
  challenges.delete(nonce)
  return c.did === did && c.expires >= Date.now()
}

// ---------------------------------------------------------------------------
// Firebase ID token verification (optional second factor)
// ---------------------------------------------------------------------------
let firebaseAuth: any = null

export function firebaseEnabled(): boolean {
  return !!process.env.FIREBASE_PROJECT_ID
}

export async function verifyFirebaseIdToken(idToken: string): Promise<{ uid: string; email?: string }> {
  if (!firebaseEnabled()) throw new Error("Firebase verification is not configured (set FIREBASE_PROJECT_ID)")
  if (!firebaseAuth) {
    // Verifying ID tokens only needs the project ID: firebase-admin fetches Google's public keys.
    const { initializeApp, getApps, cert } = require("firebase-admin/app")
    const { getAuth } = require("firebase-admin/auth")
    const options: any = { projectId: process.env.FIREBASE_PROJECT_ID }
    if (process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
      options.credential = cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON))
    }
    const app = getApps().find((a: any) => a.name === "trust") || initializeApp(options, "trust")
    firebaseAuth = getAuth(app)
  }
  // Revocation checks call the Firebase Admin API, which needs a service account.
  const decoded = await firebaseAuth.verifyIdToken(idToken, !!process.env.FIREBASE_SERVICE_ACCOUNT_JSON)
  return { uid: decoded.uid, email: decoded.email }
}

/** Test hook */
export function __setFirebaseVerifier(fn: ((t: string) => Promise<{ uid: string; email?: string }>) | null) {
  firebaseAuth = fn ? { verifyIdToken: fn } : null
}
