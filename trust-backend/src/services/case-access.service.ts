import { v4 as uuidv4 } from "uuid"
import { supabase } from "../lib/supabase"
import { hyperledgerService } from "./hyperledger.service"
import { userService } from "./user.service"
import { insertAuditRow } from "./audit-row.service"

/**
 * Case-level access control with time-bound delegation.
 *
 * OPA decides what a ROLE may do (e.g. analysts may flag). This service decides WHICH CASES a
 * person may touch:
 *   - judiciary, auditors and admins can read every case (oversight); only admins and case
 *     members can add evidence
 *   - the investigator who opens a case (first upload) owns it
 *   - the owner (or an admin) can delegate "read" or "contribute" access to another DID for a
 *     limited time; the grant, its revocation and its expiry are all ledger events
 *
 * CASE_ACCESS_MODE=open turns case scoping off (every approved role sees every case).
 */

export type CasePermission = "read" | "contribute"
export const OVERSIGHT_ROLES = ["admin", "judiciary", "auditor", "analyst"]
const MAX_HOURS = () => Number(process.env.MAX_DELEGATION_HOURS || 720)

export function caseAccessMode(): "restricted" | "open" {
  return String(process.env.CASE_ACCESS_MODE || "").trim().toLowerCase() === "open" ? "open" : "restricted"
}

export interface Actor { did: string; role: string; mspId: string; status: string }

export interface CaseRow { case_id: string; owner_did: string; created_at: string; tx_hash: string; block_number?: number }
export interface GrantRow {
  id: string; case_id: string; grantee_did: string; permission: CasePermission; granted_by: string
  expires_at: string; revoked_at: string | null; revoked_by: string | null; expiry_recorded: boolean
  tx_hash: string; created_at: string
}

export class CaseAccessError extends Error {
  constructor(message: string, public status = 403) {
    super(message)
    this.name = "CaseAccessError"
  }
}

const now = () => new Date().toISOString()
const isActive = (g: GrantRow) => !g.revoked_at && new Date(g.expires_at).getTime() > Date.now()

async function audit(logId: string, caseId: string, action: string, by: Actor, details: object) {
  const ledger = await hyperledgerService.recordAudit({
    logId, targetId: caseId, caseId, action, performedByDid: by.did, mspId: by.mspId, details: JSON.stringify(details)
  })
  await insertAuditRow({
    id: logId, evidence_id: caseId, case_id: caseId, action, performed_by: by.did,
    tx_hash: ledger.txId, block_number: ledger.blockNumber, details: JSON.stringify(details)
  })
  return ledger
}

/** Every DID this person has held (current + retired by key recovery): ownership and grants follow the person. */
async function didsOf(actor: Actor): Promise<string[]> {
  const u = await userService.getUserByDid(actor.did)
  return [actor.did, ...((u?.didHistory || []).map(h => h.did))]
}

class CaseAccessService {
  async getCase(caseId: string): Promise<CaseRow | null> {
    const { data, error } = await supabase.from("cases").select("*").eq("case_id", caseId).maybeSingle()
    if (error) throw new Error(error.message)
    return data
  }

  async grantsFor(caseId: string): Promise<GrantRow[]> {
    const { data, error } = await supabase.from("case_access").select("*").eq("case_id", caseId).order("created_at", { ascending: false })
    if (error) throw new Error(error.message)
    return data || []
  }

  private async activeGrantsOf(dids: string[]): Promise<GrantRow[]> {
    const { data, error } = await supabase.from("case_access").select("*").in("grantee_did", dids)
    if (error) throw new Error(error.message)
    return (data || []).filter(isActive)
  }

  /** null = every case (oversight role or open mode); otherwise the set of case IDs with their permission. */
  async accessibleCases(actor: Actor): Promise<Map<string, CasePermission | "owner"> | null> {
    if (caseAccessMode() === "open" || OVERSIGHT_ROLES.includes(actor.role)) return null
    const map = new Map<string, CasePermission | "owner">()
    const dids = await didsOf(actor)
    const { data: owned } = await supabase.from("cases").select("*").in("owner_did", dids)
    for (const c of owned || []) map.set(c.case_id, "owner")
    for (const g of await this.activeGrantsOf(dids)) {
      const prev = map.get(g.case_id)
      if (prev === "owner" || prev === "contribute") continue
      map.set(g.case_id, g.permission)
    }
    return map
  }

  /** Throws CaseAccessError unless the actor may read (or contribute to) the case. */
  async assert(actor: Actor, caseId: string, need: CasePermission): Promise<void> {
    if (caseAccessMode() === "open") return
    if (actor.role === "admin") return
    if (need === "read" && OVERSIGHT_ROLES.includes(actor.role)) return
    const c = await this.getCase(caseId)
    if (!c) {
      if (need === "contribute") return // a new case: the uploader opens it and becomes its owner
      throw new CaseAccessError(`Case ${caseId} does not exist`, 404)
    }
    const dids = await didsOf(actor)
    if (dids.includes(c.owner_did)) return
    const grants = (await this.activeGrantsOf(dids)).filter(g => g.case_id === caseId)
    if (grants.some(g => need === "read" || g.permission === "contribute")) return
    throw new CaseAccessError(
      `No ${need} access to case ${caseId}. Ask the case owner (${c.owner_did}) or an administrator for a time-limited delegation.`
    )
  }

  /** Called on the first upload into a case: records ownership on the ledger. */
  async openCaseIfNew(caseId: string, actor: Actor): Promise<CaseRow | null> {
    if (await this.getCase(caseId)) return null
    const ledger = await audit(`LOG-${uuidv4().slice(0, 8).toUpperCase()}`, caseId, "case_opened", actor, { owner: actor.did })
    const row: CaseRow = { case_id: caseId, owner_did: actor.did, created_at: now(), tx_hash: ledger.txId, block_number: ledger.blockNumber }
    const { error } = await supabase.from("cases").insert(row)
    if (error && !/duplicate/i.test(error.message)) throw new Error(error.message)
    return row
  }

  async grant(caseId: string, by: Actor, p: { granteeDid?: string; granteeEmail?: string; permission: CasePermission; hours: number }): Promise<GrantRow> {
    const c = await this.getCase(caseId)
    if (!c) throw new CaseAccessError(`Case ${caseId} does not exist`, 404)
    if (by.role !== "admin" && !(await didsOf(by)).includes(c.owner_did)) throw new CaseAccessError("Only the case owner or an administrator can delegate access")
    if (!["read", "contribute"].includes(p.permission)) throw new CaseAccessError("permission must be 'read' or 'contribute'", 400)
    const hours = Number(p.hours)
    if (!Number.isFinite(hours) || hours <= 0 || hours > MAX_HOURS()) throw new CaseAccessError(`expiresInHours must be between 1 and ${MAX_HOURS()}`, 400)

    const grantee = p.granteeDid ? await userService.getUserByDid(p.granteeDid) : p.granteeEmail ? await userService.getUserByEmail(p.granteeEmail) : undefined
    if (!grantee) throw new CaseAccessError("Grantee not found in the identity registry", 404)
    if (grantee.status !== "approved") throw new CaseAccessError("Grantee account is not approved", 400)
    if (grantee.did === c.owner_did) throw new CaseAccessError("The case owner already has full access", 400)
    if (p.permission === "contribute" && !["investigator", "analyst", "admin"].includes(grantee.role)) {
      throw new CaseAccessError(`A ${grantee.role} cannot contribute evidence; grant 'read' instead`, 400)
    }

    const id = `GRANT-${uuidv4().slice(0, 8).toUpperCase()}`
    const expiresAt = new Date(Date.now() + hours * 3600 * 1000).toISOString()
    const ledger = await audit(`LOG-${uuidv4().slice(0, 8).toUpperCase()}`, caseId, "access_granted", by, {
      grantId: id, grantee: grantee.did, permission: p.permission, expiresAt
    })
    const row: GrantRow = {
      id, case_id: caseId, grantee_did: grantee.did, permission: p.permission, granted_by: by.did,
      expires_at: expiresAt, revoked_at: null, revoked_by: null, expiry_recorded: false, tx_hash: ledger.txId, created_at: now()
    }
    const { error } = await supabase.from("case_access").insert(row)
    if (error) throw new Error(error.message)
    return row
  }

  async revoke(caseId: string, grantId: string, by: Actor): Promise<GrantRow> {
    const c = await this.getCase(caseId)
    const { data: g } = await supabase.from("case_access").select("*").eq("id", grantId).maybeSingle()
    if (!c || !g || g.case_id !== caseId) throw new CaseAccessError("Delegation not found", 404)
    const byDids = await didsOf(by)
    if (by.role !== "admin" && !byDids.includes(c.owner_did) && !byDids.includes(g.granted_by)) {
      throw new CaseAccessError("Only the case owner, the grantor or an administrator can revoke this delegation")
    }
    if (!isActive(g)) throw new CaseAccessError("Delegation is already revoked or expired", 400)
    await audit(`LOG-${uuidv4().slice(0, 8).toUpperCase()}`, caseId, "access_revoked", by, { grantId, grantee: g.grantee_did })
    const update = { revoked_at: now(), revoked_by: by.did }
    const { error } = await supabase.from("case_access").update(update).eq("id", grantId)
    if (error) throw new Error(error.message)
    return { ...g, ...update }
  }

  /** Writes an "access_expired" ledger event once for every delegation that has run out. */
  async recordExpiries(): Promise<number> {
    const { data } = await supabase.from("case_access").select("*").eq("expiry_recorded", false)
    const system: Actor = { did: "did:trust:system:gateway", role: "system", mspId: "SystemMSP", status: "approved" }
    let n = 0
    for (const g of (data || []) as GrantRow[]) {
      if (g.revoked_at) {
        await supabase.from("case_access").update({ expiry_recorded: true }).eq("id", g.id)
        continue
      }
      if (new Date(g.expires_at).getTime() > Date.now()) continue
      await audit(`LOG-${uuidv4().slice(0, 8).toUpperCase()}`, g.case_id, "access_expired", system, { grantId: g.id, grantee: g.grantee_did })
      await supabase.from("case_access").update({ expiry_recorded: true }).eq("id", g.id)
      n++
    }
    return n
  }
}

export const caseAccessService = new CaseAccessService()
