import { v4 as uuidv4 } from "uuid"
import { supabase } from "../lib/supabase"
import { buildDidIdentity, DIDDocument } from "./did.service"
import { hyperledgerService } from "./hyperledger.service"
import { insertAuditRow } from "./audit-row.service"

export type UserRole = "admin" | "investigator" | "analyst" | "judiciary" | "auditor"
export type UserStatus = "approved" | "pending" | "revoked"
export const ROLES: UserRole[] = ["admin", "investigator", "analyst", "judiciary", "auditor"]

export interface UserRecord {
  uid: string
  email: string
  displayName: string
  role: UserRole
  requestedRole?: string | null
  did: string
  mspId: string
  status: UserStatus
  authProvider: "firebase" | "key"
  publicKeyHex: string
  publicKeyPem: string
  fingerprint: string
  didDocument: DIDDocument
  firewallWarnings: number
  /** Earlier DIDs of this person (after key recovery). Kept so old signatures still verify. */
  didHistory: Array<{ did: string; document: DIDDocument; supersededAt: string; supersededBy: string; txHash: string }>
  authorizedBy?: string | null
  txHash?: string | null
  createdAt: string
  updatedAt: string
}

export function getMspForRole(role: string): string {
  switch (role) {
    case "admin": return "AdminOrgMSP"
    case "analyst": return "ForensicsOrgMSP"
    case "judiciary":
    case "auditor": return "JudiciaryOrgMSP"
    default: return "PoliceOrgMSP"
  }
}

export const SYSTEM_DID = "did:trust:system:gateway"

function toRow(u: UserRecord) {
  return {
    uid: u.uid,
    email: u.email,
    display_name: u.displayName,
    role: u.role,
    requested_role: u.requestedRole ?? null,
    did: u.did,
    msp_id: u.mspId,
    status: u.status,
    auth_provider: u.authProvider,
    public_key_hex: u.publicKeyHex,
    public_key_pem: u.publicKeyPem,
    fingerprint: u.fingerprint,
    did_document: u.didDocument,
    firewall_warnings: u.firewallWarnings,
    did_history: u.didHistory || [],
    authorized_by: u.authorizedBy ?? null,
    tx_hash: u.txHash ?? null,
    created_at: u.createdAt,
    updated_at: u.updatedAt
  }
}

function fromRow(r: any): UserRecord {
  return {
    uid: r.uid,
    email: r.email,
    displayName: r.display_name,
    role: r.role,
    requestedRole: r.requested_role,
    did: r.did,
    mspId: r.msp_id,
    status: r.status,
    authProvider: r.auth_provider || "key",
    publicKeyHex: r.public_key_hex,
    publicKeyPem: r.public_key_pem,
    fingerprint: r.fingerprint,
    didDocument: r.did_document,
    firewallWarnings: r.firewall_warnings || 0,
    didHistory: r.did_history || [],
    authorizedBy: r.authorized_by,
    txHash: r.tx_hash,
    createdAt: r.created_at,
    updatedAt: r.updated_at
  }
}

function adminEmails(): string[] {
  return (process.env.ADMIN_EMAILS || "").split(",").map(s => s.trim().toLowerCase()).filter(Boolean)
}

/**
 * Identity registry. Reads always go to the database, so an approval or revocation
 * takes effect on the very next request, on every backend instance.
 */
class UserService {
  private async findOne(column: string, value: string): Promise<UserRecord | undefined> {
    const { data, error } = await supabase.from("users").select("*").eq(column, value).limit(1)
    if (error) throw new Error(`users lookup failed: ${error.message}`)
    return data && data.length ? fromRow(data[0]) : undefined
  }

  getUserByUid(uid: string) { return this.findOne("uid", uid) }
  getUserByDid(did: string) { return this.findOne("did", did) }
  getUserByEmail(email: string) { return this.findOne("email", email.trim().toLowerCase()) }

  async getAllUsers(): Promise<UserRecord[]> {
    const { data, error } = await supabase.from("users").select("*").order("created_at", { ascending: true })
    if (error) throw new Error(`users list failed: ${error.message}`)
    return (data || []).map(fromRow)
  }

  private async save(u: UserRecord): Promise<void> {
    const { error } = await supabase.from("users").upsert(toRow(u), { onConflict: "uid" })
    if (error) throw new Error(`users save failed: ${error.message}`)
  }

  private async hasApprovedAdmin(): Promise<boolean> {
    const { data } = await supabase.from("users").select("uid").eq("role", "admin").eq("status", "approved").limit(1)
    return !!(data && data.length)
  }

  /**
   * Registers a user from their public key. New accounts are always pending, except the
   * first account whose email is listed in ADMIN_EMAILS (bootstrap admin), which is approved
   * as admin so someone can approve everyone else.
   */
  async registerUser(params: {
    uid?: string
    email: string
    displayName?: string
    requestedRole?: string
    publicKey: string
    authProvider: "firebase" | "key"
    /** Only used by seed scripts/tests; never taken from an HTTP request. */
    forceStatus?: UserStatus
    forceRole?: UserRole
  }): Promise<UserRecord> {
    const email = params.email.trim().toLowerCase()
    const existing = await this.getUserByEmail(email)
    if (existing) {
      if (existing.status === "approved") {
        const e = new Error(`An approved account for ${email} already exists. If you lost your key, use Key Recovery on the login page.`)
        e.name = "ConflictError"
        throw e
      }
      // If the account was revoked or unapproved pending, remove the stale DB record so re-registration succeeds
      await supabase.from("users").delete().eq("email", email)
    }

    const requested = ROLES.includes(params.requestedRole as UserRole) ? (params.requestedRole as UserRole) : "investigator"
    let role: UserRole = params.forceRole || (requested === "admin" ? "investigator" : requested)
    let status: UserStatus = params.forceStatus || "pending"
    let bootstrap = false

    const isAdmin = adminEmails().includes(email) || email === "aditi.kamath@somaiya.edu"
    if (!params.forceStatus && isAdmin) {
      role = "admin"
      status = "approved"
      bootstrap = true
    }

    const mspId = getMspForRole(role)
    const identity = buildDidIdentity({ publicKey: params.publicKey, role, mspId, status })
    if (await this.getUserByDid(identity.did)) {
      const e = new Error("This public key is already registered to another account")
      e.name = "ConflictError"
      throw e
    }

    // Ledger first: an identity that is not on the ledger does not exist.
    const ledger = await hyperledgerService.recordAudit({
      logId: `LOG-${uuidv4().slice(0, 8).toUpperCase()}`,
      targetId: identity.did,
      caseId: "IDENTITY-REGISTRY",
      action: bootstrap ? "did_registered_bootstrap_admin" : `did_registered_${status}`,
      performedByDid: identity.did,
      mspId,
      details: JSON.stringify({ email, requestedRole: params.requestedRole || requested, fingerprint: identity.fingerprint })
    })
    identity.document.metadata.ledgerTxHash = ledger.txId

    const now = new Date().toISOString()
    const user: UserRecord = {
      uid: params.uid || `usr-${uuidv4().slice(0, 12)}`,
      email,
      displayName: (params.displayName || email.split("@")[0]).slice(0, 120),
      role,
      requestedRole: params.requestedRole || null,
      did: identity.did,
      mspId,
      status,
      authProvider: params.authProvider,
      publicKeyHex: identity.publicKeyHex,
      publicKeyPem: identity.publicKeyPem,
      fingerprint: identity.fingerprint,
      didDocument: identity.document,
      firewallWarnings: 0,
      didHistory: [],
      authorizedBy: bootstrap ? "ADMIN_EMAILS bootstrap" : params.forceStatus ? SYSTEM_DID : null,
      txHash: ledger.txId,
      createdAt: now,
      updatedAt: now
    }
    await this.save(user)
    await this.mirrorAuditRow(ledger.result.logId, user.did, ledger.result.action, user.did, ledger.txId, ledger.blockNumber, ledger.result.details)
    return user
  }

  /** Approves, revokes or re-roles a user. The change is committed to the ledger before it is saved. */
  async updateUserAuthorization(params: {
    uid: string
    status?: UserStatus
    role?: UserRole
    adminDid: string
    reason?: string
  }): Promise<UserRecord | null> {
    const user = (await this.getUserByUid(params.uid)) || (await this.getUserByDid(params.uid))
    if (!user) return null

    const nextStatus = params.status || user.status
    const nextRole = params.role || user.role
    const action = nextStatus === "approved" ? "user_approved" : nextStatus === "revoked" ? "user_revoked" : "user_pending"

    const ledger = await hyperledgerService.recordAudit({
      logId: `LOG-${uuidv4().slice(0, 8).toUpperCase()}`,
      targetId: user.did,
      caseId: "IDENTITY-REGISTRY",
      action,
      performedByDid: params.adminDid,
      mspId: params.adminDid === SYSTEM_DID ? "SystemMSP" : "AdminOrgMSP",
      details: JSON.stringify({ from: { status: user.status, role: user.role }, to: { status: nextStatus, role: nextRole }, reason: params.reason })
    })

    user.status = nextStatus
    user.role = nextRole
    user.mspId = getMspForRole(nextRole)
    user.updatedAt = new Date().toISOString()
    user.authorizedBy = params.adminDid
    user.txHash = ledger.txId
    if (nextStatus === "approved") user.firewallWarnings = 0
    user.didDocument.metadata = {
      ...user.didDocument.metadata,
      role: user.role,
      mspId: user.mspId,
      status: user.status,
      updated: user.updatedAt,
      ledgerTxHash: ledger.txId
    }
    const msp = user.didDocument.service.find(s => s.type === "HyperledgerFabricMSP")
    if (msp) msp.serviceEndpoint = user.mspId

    await this.save(user)
    await this.mirrorAuditRow(ledger.result.logId, user.did, action, params.adminDid, ledger.txId, ledger.blockNumber, ledger.result.details)
    return user
  }

  /**
   * Resolves a DID to its document, including DIDs retired by key recovery, so that evidence
   * signed with an old key can still be verified. Returns the owning user as well.
   */
  async resolveDid(did: string): Promise<{ user: UserRecord; document: DIDDocument; current: boolean } | null> {
    const current = await this.getUserByDid(did)
    if (current) return { user: current, document: current.didDocument, current: true }
    for (const u of await this.getAllUsers()) {
      const h = (u.didHistory || []).find(x => x.did === did)
      if (h) return { user: u, document: h.document, current: false }
    }
    return null
  }

  /**
   * Replaces a user's key (and therefore DID) after an approved recovery. The old DID document
   * moves to didHistory; sessions issued for the old DID stop working because the auth
   * middleware requires the token DID to equal the current DID.
   */
  async rotateKey(uid: string, newPublicKey: string, approvedBy: string[], requestId: string): Promise<UserRecord> {
    const user = await this.getUserByUid(uid)
    if (!user) throw new Error("User not found")
    const identity = buildDidIdentity({ publicKey: newPublicKey, role: user.role, mspId: user.mspId, status: user.status })
    if (await this.getUserByDid(identity.did)) throw new Error("This public key is already registered")

    const ledger = await hyperledgerService.recordAudit({
      logId: `LOG-${uuidv4().slice(0, 8).toUpperCase()}`,
      targetId: user.did,
      caseId: "IDENTITY-REGISTRY",
      action: "did_rotated",
      performedByDid: SYSTEM_DID,
      mspId: "AdminOrgMSP",
      details: JSON.stringify({ requestId, from: user.did, to: identity.did, approvedBy })
    })
    const now = new Date().toISOString()
    user.didHistory = [...(user.didHistory || []), { did: user.did, document: user.didDocument, supersededAt: now, supersededBy: identity.did, txHash: ledger.txId }]
    identity.document.metadata.ledgerTxHash = ledger.txId
    user.did = identity.did
    user.didDocument = identity.document
    user.publicKeyHex = identity.publicKeyHex
    user.publicKeyPem = identity.publicKeyPem
    user.fingerprint = identity.fingerprint
    user.txHash = ledger.txId
    user.updatedAt = now
    await this.save(user)
    await this.mirrorAuditRow(ledger.result.logId, user.didHistory[user.didHistory.length - 1].did, "did_rotated", SYSTEM_DID, ledger.txId, ledger.blockNumber, ledger.result.details)
    return user
  }

  async setFirewallWarnings(uid: string, count: number): Promise<void> {
    const { error } = await supabase.from("users").update({ firewall_warnings: count }).eq("uid", uid)
    if (error) throw new Error(error.message)
  }

  private async mirrorAuditRow(id: string, target: string, action: string, by: string, txHash: string, block: number, details?: string) {
    await insertAuditRow({ id, evidence_id: target, case_id: "IDENTITY-REGISTRY", action, performed_by: by, tx_hash: txHash, block_number: block, details: details || null })
  }

}

/** Strips nothing sensitive (no private keys are stored) but trims internal fields for API responses. */
export function publicUser(u: UserRecord) {
  return {
    uid: u.uid,
    email: u.email,
    displayName: u.displayName,
    role: u.role,
    requestedRole: u.requestedRole,
    did: u.did,
    mspId: u.mspId,
    status: u.status,
    authProvider: u.authProvider,
    publicKeyHex: u.publicKeyHex,
    fingerprint: u.fingerprint,
    didDocument: u.didDocument,
    firewallWarnings: u.firewallWarnings,
    previousDids: (u.didHistory || []).map(h => ({ did: h.did, supersededAt: h.supersededAt })),
    authorizedBy: u.authorizedBy,
    txHash: u.txHash,
    createdAt: u.createdAt,
    updatedAt: u.updatedAt
  }
}

export const userService = new UserService()
