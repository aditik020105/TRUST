import { Response } from "express"
import { AuthRequest } from "../middleware/auth.middleware"
import { caseAccessService, caseAccessMode, OVERSIGHT_ROLES } from "../services/case-access.service"
import { supabase } from "../lib/supabase"

// GET /api/cases  -> cases visible to the caller, with their access level and active delegations
export async function listCases(req: AuthRequest, res: Response) {
  const { data: cases, error } = await supabase.from("cases").select("*").order("created_at", { ascending: false })
  if (error) return res.status(500).json({ success: false, error: error.message })
  const visible = await caseAccessService.accessibleCases(req.user!)
  const out: any[] = []
  for (const c of cases || []) {
    if (visible && !visible.has(c.case_id)) continue
    const access = visible?.get(c.case_id) === "owner" || c.owner_did === req.user!.did ? "owner" : visible ? visible.get(c.case_id) : OVERSIGHT_ROLES.includes(req.user!.role) ? "oversight" : "open"
    const grants = access === "owner" || req.user!.role === "admin" || OVERSIGHT_ROLES.includes(req.user!.role)
      ? await caseAccessService.grantsFor(c.case_id)
      : []
    out.push({ caseId: c.case_id, ownerDid: c.owner_did, createdAt: c.created_at, txHash: c.tx_hash, access, grants: grants.map(mapGrant) })
  }
  res.json({ success: true, mode: caseAccessMode(), data: out })
}

function mapGrant(g: any) {
  const active = !g.revoked_at && new Date(g.expires_at).getTime() > Date.now()
  return {
    id: g.id, caseId: g.case_id, granteeDid: g.grantee_did, permission: g.permission, grantedBy: g.granted_by,
    expiresAt: g.expires_at, revokedAt: g.revoked_at, revokedBy: g.revoked_by, txHash: g.tx_hash, createdAt: g.created_at,
    state: g.revoked_at ? "revoked" : active ? "active" : "expired"
  }
}

// POST /api/cases/:caseId/access { granteeDid | granteeEmail, permission, expiresInHours }
export async function grantAccess(req: AuthRequest, res: Response) {
  const { granteeDid, granteeEmail, permission = "read", expiresInHours } = req.body || {}
  const g = await caseAccessService.grant(String(req.params.caseId), req.user!, {
    granteeDid, granteeEmail, permission, hours: Number(expiresInHours)
  })
  res.status(201).json({ success: true, data: mapGrant(g) })
}

// POST /api/cases/:caseId/access/:grantId/revoke
export async function revokeAccess(req: AuthRequest, res: Response) {
  const g = await caseAccessService.revoke(String(req.params.caseId), String(req.params.grantId), req.user!)
  res.json({ success: true, data: mapGrant(g) })
}
