import { Request, Response } from "express"
import { userService, publicUser } from "../services/user.service"
import { verifyWithDocument, signingPayloads } from "../services/did.service"
import {
  createChallenge, consumeChallenge, issueSessionToken, firebaseEnabled, verifyFirebaseIdToken, sessionTtlMinutes
} from "../services/auth.service"
import { AuthRequest } from "../middleware/auth.middleware"
import { recoveryService, RecoveryError } from "../services/recovery.service"

/** POST /api/auth/challenge { email } | { did } -> one-time nonce to sign */
export async function requestChallenge(req: Request, res: Response) {
  const { email, did } = req.body || {}
  if (!email && !did) return res.status(400).json({ success: false, error: "email or did is required" })

  const user = did ? await userService.getUserByDid(String(did)) : await userService.getUserByEmail(String(email))
  if (!user) return res.status(404).json({ success: false, code: "NOT_REGISTERED", error: "No identity is registered for that email or DID" })

  const { nonce, expiresAt } = createChallenge(user.did)
  res.json({
    success: true,
    data: {
      did: user.did,
      nonce,
      payload: signingPayloads.login(user.did, nonce),
      expiresAt,
      firebaseRequired: firebaseEnabled() && user.authProvider === "firebase"
    }
  })
}

/** POST /api/auth/verify { did, nonce, signatureHex, firebaseIdToken? } -> session JWT */
export async function verifyChallenge(req: Request, res: Response) {
  const { did, nonce, signatureHex, firebaseIdToken } = req.body || {}
  if (!did || !nonce || !signatureHex) {
    return res.status(400).json({ success: false, error: "did, nonce and signatureHex are required" })
  }
  if (!consumeChallenge(String(nonce), String(did))) {
    return res.status(401).json({ success: false, code: "CHALLENGE_INVALID", error: "Challenge expired, already used, or issued for another DID" })
  }
  const user = await userService.getUserByDid(String(did))
  if (!user) return res.status(401).json({ success: false, code: "IDENTITY_UNKNOWN", error: "Unknown DID" })

  const proof = verifyWithDocument(user.didDocument, signingPayloads.login(user.did, String(nonce)), String(signatureHex))
  if (!proof.verified) {
    return res.status(401).json({ success: false, code: "SIGNATURE_INVALID", error: proof.reason })
  }

  if (firebaseEnabled() && user.authProvider === "firebase") {
    if (!firebaseIdToken) return res.status(401).json({ success: false, code: "FIREBASE_REQUIRED", error: "Firebase ID token required for this account" })
    try {
      const fb = await verifyFirebaseIdToken(String(firebaseIdToken))
      if (fb.uid !== user.uid) throw new Error("Firebase account does not match this identity")
    } catch (err: any) {
      return res.status(401).json({ success: false, code: "FIREBASE_INVALID", error: err.message || "Invalid Firebase token" })
    }
  }

  const session = issueSessionToken(user)
  res.json({ success: true, data: { token: session.token, expiresAt: session.expiresAt, ttlMinutes: sessionTtlMinutes(), user: publicUser(user), proof } })
}

/**
 * POST /api/users/register { email, displayName, requestedRole, publicKeyHex, firebaseIdToken? }
 * The browser generates the Ed25519 keypair and sends only the public key.
 * Status is always pending (except the ADMIN_EMAILS bootstrap admin); it cannot be set by the client.
 */
export async function registerUser(req: Request, res: Response) {
  const { email, displayName, requestedRole, role, publicKeyHex, firebaseIdToken } = req.body || {}
  if (!email || typeof email !== "string" || !/^[^@\s]+@[^@\s]+\.[^@\s]+$/.test(email)) {
    return res.status(400).json({ success: false, error: "A valid email is required" })
  }
  if (!publicKeyHex) return res.status(400).json({ success: false, error: "publicKeyHex (Ed25519 public key) is required" })

  let uid: string | undefined
  let authProvider: "firebase" | "key" = "key"
  if (firebaseEnabled()) {
    if (!firebaseIdToken) {
      return res.status(401).json({ success: false, code: "FIREBASE_REQUIRED", error: "Sign up with Firebase first; firebaseIdToken is required" })
    }
    try {
      const fb = await verifyFirebaseIdToken(String(firebaseIdToken))
      if (!fb.email || fb.email.toLowerCase() !== email.trim().toLowerCase()) throw new Error("Firebase email does not match")
      uid = fb.uid
      authProvider = "firebase"
    } catch (err: any) {
      return res.status(401).json({ success: false, code: "FIREBASE_INVALID", error: err.message || "Invalid Firebase token" })
    }
  }

  try {
    const user = await userService.registerUser({
      uid,
      email,
      displayName,
      requestedRole: requestedRole || role,
      publicKey: String(publicKeyHex),
      authProvider
    })
    res.status(201).json({
      success: true,
      data: publicUser(user),
      message: user.status === "pending"
        ? "Identity registered. Your account is PENDING administrator approval."
        : "Bootstrap administrator registered and approved."
    })
  } catch (err: any) {
    if (err.name === "ConflictError") return res.status(409).json({ success: false, error: err.message })
    if (/publicKey/.test(err.message)) return res.status(400).json({ success: false, error: err.message })
    throw err
  }
}

/** GET /api/users/me */
export async function getCurrentUser(req: AuthRequest, res: Response) {
  res.json({ success: true, data: publicUser(req.account!), sessionExpiresAt: req.sessionExpiresAt })
}

/**
 * POST /api/recovery/request { email, newPublicKeyHex, reason, firebaseIdToken? }
 * The browser generates a NEW key; nothing changes until enough administrators approve.
 * Administrators must confirm the person's identity out of band before approving.
 */
export async function requestRecovery(req: Request, res: Response) {
  const { email, newPublicKeyHex, reason, firebaseIdToken } = req.body || {}
  if (!email || !newPublicKeyHex) return res.status(400).json({ success: false, error: "email and newPublicKeyHex are required" })
  const user = await userService.getUserByEmail(String(email))
  if (!user) return res.status(404).json({ success: false, error: "No identity is registered for that email" })
  if (firebaseEnabled() && user.authProvider === "firebase") {
    try {
      const fb = await verifyFirebaseIdToken(String(firebaseIdToken || ""))
      if (fb.uid !== user.uid) throw new Error("Firebase account does not match")
    } catch (err: any) {
      return res.status(401).json({ success: false, code: "FIREBASE_REQUIRED", error: `Sign in with Firebase to request recovery: ${err.message}` })
    }
  }
  try {
    const r = await recoveryService.request(user, String(newPublicKeyHex), String(reason || ""))
    res.status(201).json({
      success: true,
      data: { id: r.id, newDid: r.new_did, requiredApprovals: r.required_approvals, reducedQuorum: r.reduced_quorum, expiresAt: r.expires_at },
      message: `Recovery requested. ${r.required_approvals} administrator approval(s) are needed before your new key works.`
    })
  } catch (err: any) {
    if (err instanceof RecoveryError) return res.status(err.status).json({ success: false, error: err.message })
    if (/publicKey/.test(err.message)) return res.status(400).json({ success: false, error: err.message })
    throw err
  }
}
