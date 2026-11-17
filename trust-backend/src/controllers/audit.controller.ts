import { Response } from "express"
import { supabase } from "../lib/supabase"
import { AuthRequest } from "../middleware/auth.middleware"
import { caseAccessService, OVERSIGHT_ROLES } from "../services/case-access.service"

// GET /api/audit-log?evidenceId=&caseId=&performedBy=&action=&limit=
export async function getAuditLog(req: AuthRequest, res: Response) {
  const { evidenceId, caseId, performedBy, action } = req.query
  const limit = Math.min(Math.max(Number(req.query.limit) || 500, 1), 2000)

  let query = supabase.from("audit_log").select("*")
  if (evidenceId) query = query.eq("evidence_id", String(evidenceId))
  if (caseId) query = query.eq("case_id", String(caseId))
  if (performedBy) query = query.eq("performed_by", String(performedBy))
  if (action) query = query.eq("action", String(action))

  const { data, error } = await query.order("timestamp", { ascending: false }).limit(limit)
  if (error) return res.status(500).json({ success: false, error: error.message })

  // Outside oversight roles, only events of cases the caller can access (and their own identity events).
  const visible = await caseAccessService.accessibleCases(req.user!)
  const rows = (data || []).filter((e: any) =>
    OVERSIGHT_ROLES.includes(req.user!.role) || !visible
      ? true
      : e.case_id === "IDENTITY-REGISTRY" ? e.evidence_id === req.user!.did : visible.has(e.case_id))

  res.json({
    success: true,
    data: rows.map((e: any) => ({
      id: e.id,
      evidenceId: e.evidence_id,
      caseId: e.case_id,
      action: e.action,
      performedBy: e.performed_by,
      timestamp: e.timestamp,
      txHash: e.tx_hash,
      blockNumber: e.block_number,
      details: e.details
    }))
  })
}
