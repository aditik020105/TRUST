import { Request, Response } from "express"
import { AuthRequest } from "../middleware/auth.middleware"
import { userService, UserRole, UserStatus, ROLES, getMspForRole, publicUser } from "../services/user.service"
import { verifyWithDocument } from "../services/did.service"
import { opaService, OpaInput } from "../services/opa.service"
import { getFirewallTelemetry, resetDdosStore, unbanClientIp } from "../middleware/ddos.middleware"
import { hyperledgerService } from "../services/hyperledger.service"
import { runReconciliation, getLastReconciliation } from "../services/reconciliation.service"
import { dbMode } from "../lib/supabase"
import { recoveryService } from "../services/recovery.service"
import { importLegacyLog } from "../services/legacy-import.service"
import { outboxStatus } from "../services/audit-row.service"

// GET /api/did  (DID Documents are public by design: anyone may resolve a DID to check a signature)
export async function listDIDs(_req: Request, res: Response) {
  const users = await userService.getAllUsers()
  res.json({ success: true, data: users.map(u => u.didDocument) })
}

// GET /api/did/:did
export async function resolveDID(req: Request, res: Response) {
  const did = decodeURIComponent(String(req.params.did))
  const found = await userService.resolveDid(did)
  if (!found) return res.status(404).json({ success: false, error: `DID Document not found for identifier: ${did}` })
  res.json({ success: true, data: found.document, current: found.current, currentDid: found.user.did })
}

// POST /api/did/verify { did, payload, signatureHex }
export async function verifyDIDSignature(req: Request, res: Response) {
  const { did, payload, signatureHex } = req.body || {}
  if (!did || payload === undefined || !signatureHex) {
    return res.status(400).json({ success: false, error: "did, payload, and signatureHex are required" })
  }
  const found = await userService.resolveDid(String(did))
  res.json({ success: true, data: { ...verifyWithDocument(found?.document, String(payload), String(signatureHex)), didIsCurrent: found?.current ?? false } })
}

// GET /api/admin/users
export async function listAllUsers(_req: AuthRequest, res: Response) {
  const users = await userService.getAllUsers()
  res.json({ success: true, data: users.map(publicUser) })
}

// PATCH /api/admin/users/:uid/authorize { status?, role? }
export async function authorizeUser(req: AuthRequest, res: Response) {
  const uid = String(req.params.uid)
  const { status, role } = (req.body || {}) as { status?: UserStatus; role?: UserRole }

  if (status && !["approved", "pending", "revoked"].includes(status)) {
    return res.status(400).json({ success: false, error: "Invalid authorization status. Must be 'approved', 'pending', or 'revoked'." })
  }
  if (role && !ROLES.includes(role)) {
    return res.status(400).json({ success: false, error: `Invalid role. Must be one of ${ROLES.join(", ")}.` })
  }
  if (!status && !role) return res.status(400).json({ success: false, error: "status or role is required" })
  if (uid === req.user!.uid && (status === "revoked" || status === "pending" || (role && role !== "admin"))) {
    return res.status(400).json({ success: false, error: "Administrators cannot revoke or demote their own account" })
  }

  const updated = await userService.updateUserAuthorization({ uid, status, role, adminDid: req.user!.did })
  if (!updated) return res.status(404).json({ success: false, error: `User '${uid}' not found in registry` })

  res.json({
    success: true,
    data: publicUser(updated),
    txHash: updated.txHash,
    message: `User ${updated.email} (${updated.did}) is now '${updated.status.toUpperCase()}' with role '${updated.role}' (${updated.mspId}).`
  })
}

// GET /api/admin/opa
export async function getOpaPolicyDashboard(_req: AuthRequest, res: Response) {
  res.json({
    success: true,
    data: {
      regoPolicy: opaService.getRegoSource(),
      roleAccessMatrix: opaService.getRoleAccessMatrix(),
      decisionLogs: opaService.getDecisionLogs(),
      rejectedLogs: opaService.getDecisionLogs({ onlyRejected: true }),
      engine: process.env.OPA_URL ? `remote OPA at ${process.env.OPA_URL} (embedded fallback)` : "embedded evaluator mirroring trust_authz.rego"
    }
  })
}

// POST /api/admin/opa/evaluate  (dry-run; never changes anything)
export async function simulateOpaPolicy(req: AuthRequest, res: Response) {
  const { role = "investigator", status = "approved", did, mspId, action = "upload_evidence", parameters = {} } = req.body || {}
  const input: OpaInput = {
    method: "SIMULATE",
    path: `/api/simulate/${action}`,
    action,
    resource: `/api/simulate/${action}`,
    user: {
      did: did !== undefined ? did : `did:trust:${role}:simulator01`,
      role,
      mspId: mspId || getMspForRole(role),
      status
    },
    parameters
  }
  const decision = await opaService.evaluate(input, false)
  res.json({ success: true, data: decision })
}

// GET /api/admin/firewall
export async function getFirewallStatus(_req: AuthRequest, res: Response) {
  res.json({ success: true, data: await getFirewallTelemetry() })
}

// POST /api/admin/firewall/reset
export async function resetFirewall(req: AuthRequest, res: Response) {
  const { ip } = req.body || {}
  if (ip) {
    await unbanClientIp(String(ip))
    return res.json({ success: true, message: `Firewall state cleared for IP ${ip}`, data: await getFirewallTelemetry() })
  }
  await resetDdosStore()
  res.json({ success: true, message: "All firewall counters, jailed IPs, and logs have been reset.", data: await getFirewallTelemetry() })
}

// GET /api/admin/ledger
export async function getLedgerStatus(_req: AuthRequest, res: Response) {
  const [info, chain] = await Promise.all([hyperledgerService.info(), hyperledgerService.verifyChain()])
  res.json({ success: true, data: { ledger: info, chain, database: dbMode, lastReconciliation: getLastReconciliation() } })
}

// POST /api/admin/reconcile
export async function reconcileNow(_req: AuthRequest, res: Response) {
  const report = await runReconciliation()
  res.json({ success: true, data: report })
}

// GET /api/admin/recovery
export async function listRecoveryRequests(_req: AuthRequest, res: Response) {
  res.json({ success: true, data: await recoveryService.list() })
}

// POST /api/admin/recovery/:id/approve
export async function approveRecovery(req: AuthRequest, res: Response) {
  const { request, rotated } = await recoveryService.approve(String(req.params.id), req.user!)
  res.json({
    success: true,
    data: request,
    message: rotated
      ? `Quorum reached: ${rotated.email} now uses ${rotated.did}; the old DID is retired.`
      : `Approval recorded (${request.approvals.length} of ${request.required_approvals}).`
  })
}

// POST /api/admin/recovery/:id/reject
export async function rejectRecovery(req: AuthRequest, res: Response) {
  res.json({ success: true, data: await recoveryService.reject(String(req.params.id), req.user!) })
}

// POST /api/admin/legacy-import  multipart: file (CSV), dryRun=true|false
export async function legacyImport(req: AuthRequest, res: Response) {
  const file = (req as any).file
  if (!file) return res.status(400).json({ success: false, error: "CSV file is required" })
  const dryRun = String(req.body?.dryRun || "false") === "true"
  const result = await importLegacyLog(file.buffer.toString("utf-8"), file.originalname, req.user!, dryRun)
  res.status(result.errors.length ? 400 : 200).json({ success: result.errors.length === 0, data: { ...result, dryRun } })
}

// GET /api/admin/connector  (case-management webhook status)
export async function connectorStatus(_req: AuthRequest, res: Response) {
  res.json({ success: true, data: await outboxStatus() })
}
