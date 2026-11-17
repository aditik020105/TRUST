import { Request, Response, NextFunction } from "express"
import { userService, UserRecord } from "../services/user.service"
import { verifySessionToken } from "../services/auth.service"

export interface AuthRequest extends Request {
  user?: {
    uid: string
    email: string
    did: string
    role: string
    mspId: string
    status: "approved" | "pending" | "revoked"
  }
  /** Full registry record (includes the DID Document for signature checks). */
  account?: UserRecord
  sessionExpiresAt?: string
}

function reject(res: Response, code: string, message: string) {
  res.status(401).json({ success: false, code, error: message })
}

/**
 * Verifies the backend-issued session JWT (signature, issuer, audience, expiry) and then
 * loads the caller from the identity registry, so role and approval status always come
 * from the registry rather than from the token.
 */
export async function authMiddleware(req: AuthRequest, res: Response, next: NextFunction) {
  const header = req.headers.authorization
  if (!header || !header.startsWith("Bearer ")) {
    return reject(res, "AUTH_REQUIRED", "Authentication required: send Authorization: Bearer <session token>")
  }

  let claims
  try {
    claims = verifySessionToken(header.slice(7).trim())
  } catch (err: any) {
    const expired = err?.name === "TokenExpiredError"
    return reject(res, expired ? "TOKEN_EXPIRED" : "TOKEN_INVALID", expired ? "Session expired. Sign in again." : "Invalid session token")
  }

  try {
    const account = await userService.getUserByUid(claims.sub)
    if (!account || account.did !== claims.did) {
      return reject(res, "IDENTITY_UNKNOWN", "Session does not match a registered identity")
    }
    req.account = account
    req.user = {
      uid: account.uid,
      email: account.email,
      did: account.did,
      role: account.role,
      mspId: account.mspId,
      status: account.status
    }
    req.sessionExpiresAt = new Date(claims.exp * 1000).toISOString()
    next()
  } catch (err) {
    next(err)
  }
}
