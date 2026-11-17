import { v4 as uuidv4 } from "uuid"
import { supabase } from "../lib/supabase"
import { buildDidIdentity } from "./did.service"
import { hyperledgerService } from "./hyperledger.service"
import { userService, SYSTEM_DID, UserRecord } from "./user.service"
import { insertAuditRow } from "./audit-row.service"

/**
 * Identity recovery for lost keys, without letting any single administrator take over an identity.
 *
 * 1. The user generates a NEW key in the browser and files a request (with their Firebase login
 *    when Firebase is enabled, which proves control of the email).
 * 2. RECOVERY_APPROVALS distinct administrators (default 2) must approve. An admin cannot approve
 *    a request for their own account. If fewer other admins exist, the quorum drops to the number
 *    available (minimum 1) and the request is marked reducedQuorum so the record shows it.
 * 3. On quorum the DID is rotated: the old DID document is kept in the user's history (old
 *    signatures still verify), and old sessions stop working.
 * Every step is a ledger event.
 */

export interface RecoveryRow {
  id: string
  uid: string
  email: string
  old_did: string
  new_did: string
  new_public_key_hex: string
  reason: string
  status: "pending" | "completed" | "rejected" | "expired"
  approvals: Array<{ did: string; at: string; txHash: string }>
  required_approvals: number
  reduced_quorum: boolean
  created_at: string
  expires_at: string
  completed_at: string | null
  tx_hash: string
}

export class RecoveryError extends Error {
  constructor(message: string, public status = 400) {
    super(message)
    this.name = "RecoveryError"
  }
}

const TTL_HOURS = () => Number(process.env.RECOVERY_TTL_HOURS || 72)

async function ledgerEvent(target: string, action: string, by: string, details: object) {
  const logId = `LOG-${uuidv4().slice(0, 8).toUpperCase()}`
  const ledger = await hyperledgerService.recordAudit({
    logId, targetId: target, caseId: "IDENTITY-REGISTRY", action, performedByDid: by, mspId: "AdminOrgMSP", details: JSON.stringify(details)
  })
  await insertAuditRow({
    id: logId, evidence_id: target, case_id: "IDENTITY-REGISTRY", action, performed_by: by,
    tx_hash: ledger.txId, block_number: ledger.blockNumber, details: JSON.stringify(details)
  })
  return ledger
}

async function otherApprovedAdmins(excludeUid: string): Promise<UserRecord[]> {
  return (await userService.getAllUsers()).filter(u => u.role === "admin" && u.status === "approved" && u.uid !== excludeUid)
}

class RecoveryService {
  async request(user: UserRecord, newPublicKeyHex: string, reason: string): Promise<RecoveryRow> {
    const { data: open } = await supabase.from("recovery_requests").select("*").eq("uid", user.uid).eq("status", "pending")
    for (const r of open || []) {
      if (new Date(r.expires_at).getTime() > Date.now()) throw new RecoveryError("A recovery request for this account is already pending", 409)
    }
    const identity = buildDidIdentity({ publicKey: newPublicKeyHex, role: user.role, mspId: user.mspId, status: user.status })
    if (await userService.resolveDid(identity.did)) throw new RecoveryError("That public key is already in use", 409)

    const admins = await otherApprovedAdmins(user.uid)
    const wanted = Math.max(1, Number(process.env.RECOVERY_APPROVALS || 2))
    if (admins.length === 0) throw new RecoveryError("No other approved administrator exists to approve a recovery", 409)
    const required = Math.min(wanted, admins.length)

    const id = `REC-${uuidv4().slice(0, 8).toUpperCase()}`
    const ledger = await ledgerEvent(user.did, "recovery_requested", SYSTEM_DID, { requestId: id, newDid: identity.did, required, reason })
    const row: RecoveryRow = {
      id, uid: user.uid, email: user.email, old_did: user.did, new_did: identity.did, new_public_key_hex: identity.publicKeyHex,
      reason: (reason || "").slice(0, 500), status: "pending", approvals: [], required_approvals: required,
      reduced_quorum: required < wanted, created_at: new Date().toISOString(),
      expires_at: new Date(Date.now() + TTL_HOURS() * 3600 * 1000).toISOString(), completed_at: null, tx_hash: ledger.txId
    }
    const { error } = await supabase.from("recovery_requests").insert(row)
    if (error) throw new Error(error.message)
    return row
  }

  async list(): Promise<RecoveryRow[]> {
    const { data, error } = await supabase.from("recovery_requests").select("*").order("created_at", { ascending: false })
    if (error) throw new Error(error.message)
    return (data || []).map((r: RecoveryRow) =>
      r.status === "pending" && new Date(r.expires_at).getTime() < Date.now() ? { ...r, status: "expired" as const } : r)
  }

  private async get(id: string): Promise<RecoveryRow> {
    const { data } = await supabase.from("recovery_requests").select("*").eq("id", id).maybeSingle()
    if (!data) throw new RecoveryError("Recovery request not found", 404)
    return data
  }

  async approve(id: string, admin: { uid: string; did: string }): Promise<{ request: RecoveryRow; rotated: UserRecord | null }> {
    const r = await this.get(id)
    if (r.status !== "pending") throw new RecoveryError(`Request is ${r.status}`)
    if (new Date(r.expires_at).getTime() < Date.now()) throw new RecoveryError("Request has expired")
    if (r.uid === admin.uid) throw new RecoveryError("Administrators cannot approve recovery of their own account", 403)
    if (r.approvals.some(a => a.did === admin.did)) throw new RecoveryError("You have already approved this request", 409)

    const ledger = await ledgerEvent(r.old_did, "recovery_approved", admin.did, { requestId: id, approval: r.approvals.length + 1, of: r.required_approvals })
    r.approvals = [...r.approvals, { did: admin.did, at: new Date().toISOString(), txHash: ledger.txId }]

    let rotated: UserRecord | null = null
    if (r.approvals.length >= r.required_approvals) {
      rotated = await userService.rotateKey(r.uid, r.new_public_key_hex, r.approvals.map(a => a.did), id)
      r.status = "completed"
      r.completed_at = new Date().toISOString()
    }
    const { error } = await supabase.from("recovery_requests").update({ approvals: r.approvals, status: r.status, completed_at: r.completed_at }).eq("id", id)
    if (error) throw new Error(error.message)
    return { request: r, rotated }
  }

  async reject(id: string, admin: { did: string }): Promise<RecoveryRow> {
    const r = await this.get(id)
    if (r.status !== "pending") throw new RecoveryError(`Request is ${r.status}`)
    await ledgerEvent(r.old_did, "recovery_rejected", admin.did, { requestId: id })
    await supabase.from("recovery_requests").update({ status: "rejected", completed_at: new Date().toISOString() }).eq("id", id)
    return { ...r, status: "rejected" }
  }
}

export const recoveryService = new RecoveryService()
