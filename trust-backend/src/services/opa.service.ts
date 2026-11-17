import fs from "fs"
import path from "path"
import axios from "axios"

export interface OpaUserContext {
  uid?: string
  email?: string
  did: string
  role: string
  mspId: string
  status: "approved" | "pending" | "revoked"
}

export interface OpaInput {
  method: string
  path: string
  action: string
  resource: string
  user: OpaUserContext
  parameters?: Record<string, any>
}

export interface OpaDecision {
  id: string
  allow: boolean
  rule: string
  reason: string
  timestamp: string
  input: OpaInput
}

export interface RoleAccessMatrixEntry {
  role: string
  mspId: string
  description: string
  allowedActions: string[]
  deniedActions: string[]
  requiredParameters: Record<string, string>
}

const MAX_OPA_LOGS = 200

export const READ_ACTIONS = ["list_evidence", "inspect_evidence", "view_evidence", "download_evidence", "verify_integrity", "read_audit_log", "export_report"]
export const ADMIN_ACTIONS = ["approve_user", "revoke_user", "manage_users", "manage_firewall", "import_legacy"]
export const OVERSIGHT_ACTIONS = ["view_policy", "audit_ledger"]

class OpaPolicyService {
  private decisionLogs: OpaDecision[] = []
  private regoSourceCache: string | null = null

  public getRegoSource(): string {
    if (this.regoSourceCache) return this.regoSourceCache
    const regoPath = path.join(process.cwd(), "policies", "trust_authz.rego")
    try {
      if (fs.existsSync(regoPath)) {
        this.regoSourceCache = fs.readFileSync(regoPath, "utf-8")
        return this.regoSourceCache
      }
    } catch (err) {
      console.warn("Could not read trust_authz.rego from disk:", err)
    }
    return `package trust.authz\ndefault allow := false`
  }

  public getRoleAccessMatrix(): RoleAccessMatrixEntry[] {
    return [
      {
        role: "admin",
        mspId: "AdminOrgMSP",
        description: "Consortium Administrator — Approves/revokes user DIDs, manages roles, monitors OPA & Firewall logs.",
        allowedActions: [
          "approve_user",
          "revoke_user",
          "manage_users",
          "manage_firewall",
          "view_policy",
          "audit_ledger",
          "list_evidence",
          "inspect_evidence",
          "view_evidence",
          "download_evidence",
          "verify_integrity",
          "upload_evidence",
          "update_evidence_status (verified | flagged | pending)",
          "read_audit_log"
        ],
        deniedActions: [],
        requiredParameters: {
          "user.status": "approved",
          "user.did": "did:trust:*",
          "user.mspId": "AdminOrgMSP"
        }
      },
      {
        role: "investigator",
        mspId: "PoliceOrgMSP",
        description: "Law Enforcement / First Responder — Collects crime-scene files, computes SHA-256 hashes, and anchors new evidence.",
        allowedActions: [
          "upload_evidence",
          "list_evidence",
          "inspect_evidence",
          "view_evidence",
          "download_evidence",
          "verify_integrity",
          "read_audit_log"
        ],
        deniedActions: [
          "update_evidence_status (verified)",
          "update_evidence_status (flagged)",
          "approve_user",
          "revoke_user"
        ],
        requiredParameters: {
          "user.status": "approved",
          "user.did": "did:trust:*",
          "user.mspId": "PoliceOrgMSP",
          "body.caseId": "non-empty string",
          "file": "multipart binary buffer"
        }
      },
      {
        role: "analyst",
        mspId: "ForensicsOrgMSP",
        description: "Forensic Lab Specialist — Inspects & downloads evidence (logged on-chain), uploads lab reports, and flags anomalies.",
        allowedActions: [
          "list_evidence",
          "inspect_evidence",
          "view_evidence",
          "download_evidence",
          "verify_integrity",
          "upload_evidence",
          "update_evidence_status (flagged | pending)",
          "read_audit_log"
        ],
        deniedActions: [
          "update_evidence_status (verified — Judicial sign-off only)",
          "approve_user",
          "revoke_user"
        ],
        requiredParameters: {
          "user.status": "approved",
          "user.did": "did:trust:*",
          "user.mspId": "ForensicsOrgMSP",
          "parameters.status": "flagged | pending"
        }
      },
      {
        role: "judiciary",
        mspId: "JudiciaryOrgMSP",
        description: "Judicial Authority / Court — Reviews chain-of-custody audit trail, verifies evidence admissibility, or flags disputes.",
        allowedActions: [
          "list_evidence",
          "inspect_evidence",
          "view_evidence",
          "download_evidence",
          "verify_integrity",
          "update_evidence_status (verified | flagged | pending)",
          "read_audit_log"
        ],
        deniedActions: [
          "approve_user / revoke_user (identity administration is admin-only)",
          "upload_evidence (Separation of duties: Court cannot fabricate/submit primary crime-scene evidence)"
        ],
        requiredParameters: {
          "user.status": "approved",
          "user.did": "did:trust:*",
          "user.mspId": "JudiciaryOrgMSP",
          "parameters.status": "verified | flagged | pending"
        }
      },
      {
        role: "auditor",
        mspId: "JudiciaryOrgMSP",
        description: "Compliance Auditor — Read-only inspection of evidence metadata and immutable blockchain audit logs.",
        allowedActions: [
          "list_evidence",
          "inspect_evidence",
          "view_evidence",
          "download_evidence",
          "verify_integrity",
          "read_audit_log",
          "view_policy",
          "audit_ledger"
        ],
        deniedActions: [
          "upload_evidence",
          "update_evidence_status (verified | flagged | pending)",
          "approve_user",
          "revoke_user"
        ],
        requiredParameters: {
          "user.status": "approved",
          "user.did": "did:trust:*"
        }
      }
    ]
  }

  /**
   * Evaluates an OPA input object against `trust.authz` Rego rules.
   * Supports optional external OPA server (if OPA_URL env var is set) with deterministic local Rego evaluation.
   */
  public async evaluate(input: OpaInput, recordLog: boolean = true): Promise<OpaDecision> {
    const opaUrl = process.env.OPA_URL
    if (opaUrl) {
      try {
        const res = await axios.post<any>(`${opaUrl.replace(/\/$/, "")}/v1/data/trust/authz`, { input }, { timeout: 1500 })
        if (res.data && res.data.result) {
          const result = res.data.result
          const decision: OpaDecision = {
            id: `OPA-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`,
            allow: Boolean(result.allow),
            rule: result.allow ? "opa_remote_allow" : "opa_remote_deny",
            reason: result.allow
              ? `Allowed by OPA server for role '${input.user.role}' (${input.user.mspId})`
              : (result.rejection_reason || "Rejected by OPA policy server"),
            timestamp: new Date().toISOString(),
            input
          }
          if (recordLog) this.logDecision(decision)
          return decision
        }
      } catch {
        // Fallback to embedded Rego engine if external OPA server is unreachable
      }
    }

    const decision = this.evaluateEmbeddedRego(input)
    if (recordLog) {
      this.logDecision(decision)
    }
    return decision
  }

  /**
   * Deterministic evaluation of `policies/trust_authz.rego` rules.
   */
  public evaluateEmbeddedRego(input: OpaInput): OpaDecision {
    const now = new Date().toISOString()
    const id = `OPA-${Date.now()}-${Math.random().toString(36).slice(2, 6).toUpperCase()}`
    const { user, action, parameters } = input

    // 1. Check User Revocation Status (`user_is_revoked`)
    if (user.status === "revoked") {
      return {
        id,
        allow: false,
        rule: "user_not_revoked",
        reason: `Server Rejection [OPA Rule: user_not_revoked]: Access Denied. Your cryptographic DID (${user.did}) has been REVOKED by the Administrator. All chain-of-custody permissions are terminated.`,
        timestamp: now,
        input
      }
    }

    // 2. Check User Pending Approval Status (`user_is_pending`)
    if (user.status === "pending") {
      return {
        id,
        allow: false,
        rule: "user_must_be_approved",
        reason: `Server Rejection [OPA Rule: user_must_be_approved]: Access Denied. Your account (DID: ${user.did}, Role: ${user.role}) is PENDING Administrator approval. An admin must approve your DID before you can interact with the ledger.`,
        timestamp: now,
        input
      }
    }

    // 3. Check W3C DID syntax (`valid_did`)
    if (!user.did || !user.did.startsWith("did:trust:")) {
      return {
        id,
        allow: false,
        rule: "valid_did",
        reason: `Server Rejection [OPA Rule: valid_did]: Malformed Decentralized Identifier (${user.did}). Must conform to W3C method 'did:trust:<identifier>'.`,
        timestamp: now,
        input
      }
    }

    // 4. Action: Read / List / Inspect / Download Evidence or Read Audit Log
    if (READ_ACTIONS.includes(action)) {
      if (["investigator", "analyst", "judiciary", "auditor", "admin"].includes(user.role)) {
        return {
          id,
          allow: true,
          rule: "allow_read_custody_records",
          reason: `OPA Policy ALLOW [allow_read_custody_records]: Approved user ${user.did} with role '${user.role}' (${user.mspId}) granted '${action}' access.`,
          timestamp: now,
          input
        }
      }
    }

    // 4a. Delegating case access: case owners (investigators) and admins; the service checks ownership
    if (action === "delegate_case_access") {
      const ok = ["investigator", "analyst", "admin"].includes(user.role)
      return {
        id,
        allow: ok,
        rule: "allow_delegation",
        reason: ok
          ? `OPA Policy ALLOW [allow_delegation]: Role '${user.role}' may delegate access to cases it owns.`
          : `Server Rejection [OPA Rule: allow_delegation]: Role '${user.role}' (${user.mspId}) cannot delegate case access.`,
        timestamp: now,
        input
      }
    }

    // 4b. Private case notes: the collecting agency, the court and admins (not forensic labs or auditors)
    if (action === "read_private_details") {
      const ok = ["investigator", "judiciary", "admin"].includes(user.role)
      return {
        id,
        allow: ok,
        rule: "allow_private_details",
        reason: ok
          ? `OPA Policy ALLOW [allow_private_details]: Role '${user.role}' may read private case notes.`
          : `Server Rejection [OPA Rule: allow_private_details]: Role '${user.role}' (${user.mspId}) may not read private case notes. Allowed: investigator, judiciary, admin.`,
        timestamp: now,
        input
      }
    }

    // 5. Action: Upload Evidence (`upload_evidence`)
    if (action === "upload_evidence") {
      if (["investigator", "analyst", "admin"].includes(user.role)) {
        return {
          id,
          allow: true,
          rule: "allow_upload_evidence",
          reason: `OPA Policy ALLOW [allow_upload_evidence]: Role '${user.role}' (${user.mspId}) is authorized to submit and anchor new evidence on Hyperledger Fabric.`,
          timestamp: now,
          input
        }
      } else {
        return {
          id,
          allow: false,
          rule: "allow_upload_evidence",
          reason: `Server Rejection [OPA Rule: allow_upload_evidence]: Role '${user.role}' (${user.mspId}) is prohibited from uploading evidence. Separation of duties restricts evidence collection to 'investigator' (PoliceOrgMSP) or 'analyst' (ForensicsOrgMSP).`,
          timestamp: now,
          input
        }
      }
    }

    // 6. Action: Update Evidence Status (`update_evidence_status`)
    if (action === "update_evidence_status") {
      const targetStatus = parameters?.status

      // If targetStatus is missing or not a valid status enum, let controller return 400 validation error
      // UNLESS the user's role isn't allowed to update status at all!
      if (targetStatus === "verified") {
        if (["judiciary", "admin"].includes(user.role)) {
          return {
            id,
            allow: true,
            rule: "allow_verify_evidence",
            reason: `OPA Policy ALLOW [allow_verify_evidence]: Role '${user.role}' (${user.mspId}) is authorized for judicial verification of evidence.`,
            timestamp: now,
            input
          }
        } else {
          return {
            id,
            allow: false,
            rule: "allow_verify_evidence",
            reason: `Server Rejection [OPA Rule: allow_verify_evidence]: Role '${user.role}' (${user.mspId}) cannot mark evidence as 'verified'. Judicial verification requires role 'judiciary' (JudiciaryOrgMSP).`,
            timestamp: now,
            input
          }
        }
      }

      if (targetStatus === "flagged" || targetStatus === "pending") {
        if (["analyst", "judiciary", "admin"].includes(user.role)) {
          return {
            id,
            allow: true,
            rule: "allow_flag_evidence",
            reason: `OPA Policy ALLOW [allow_flag_evidence]: Role '${user.role}' (${user.mspId}) is authorized to set evidence status to '${targetStatus}'.`,
            timestamp: now,
            input
          }
        } else {
          return {
            id,
            allow: false,
            rule: "allow_flag_evidence",
            reason: `Server Rejection [OPA Rule: allow_flag_evidence]: Role '${user.role}' (${user.mspId}) cannot change evidence status to '${targetStatus}'. Only 'analyst' (ForensicsOrgMSP) or 'judiciary' (JudiciaryOrgMSP) can flag or review evidence.`,
            timestamp: now,
            input
          }
        }
      }

      // If status is invalid/missing, allow through to controller for 400 Bad Request validation if role can mutate status
      if (["analyst", "judiciary", "admin"].includes(user.role)) {
        return {
          id,
          allow: true,
          rule: "allow_status_parameter_validation",
          reason: "Passed to controller for status parameter validation.",
          timestamp: now,
          input
        }
      } else {
        return {
          id,
          allow: false,
          rule: "allow_status_mutation",
          reason: `Server Rejection [OPA Rule: allow_status_mutation]: Role '${user.role}' (${user.mspId}) is not authorized to modify evidence status.`,
          timestamp: now,
          input
        }
      }
    }

    // 7. Action: Identity administration and firewall management (admin only)
    if (ADMIN_ACTIONS.includes(action)) {
      if (user.role === "admin") {
        return {
          id,
          allow: true,
          rule: "allow_admin_authorization",
          reason: `OPA Policy ALLOW [allow_admin_authorization]: Administrative identity ${user.did} authorized for '${action}'.`,
          timestamp: now,
          input
        }
      }
      return {
        id,
        allow: false,
        rule: "allow_admin_authorization",
        reason: `Server Rejection [OPA Rule: allow_admin_authorization]: Role '${user.role}' (${user.mspId}) is not authorized for '${action}'. Required role: 'admin' (AdminOrgMSP).`,
        timestamp: now,
        input
      }
    }

    // 8. Action: Oversight (policy viewer, ledger status, reconciliation): admin and auditor
    if (OVERSIGHT_ACTIONS.includes(action)) {
      if (["admin", "auditor"].includes(user.role)) {
        return {
          id,
          allow: true,
          rule: "allow_oversight",
          reason: `OPA Policy ALLOW [allow_oversight]: Role '${user.role}' may perform '${action}'.`,
          timestamp: now,
          input
        }
      }
      return {
        id,
        allow: false,
        rule: "allow_oversight",
        reason: `Server Rejection [OPA Rule: allow_oversight]: Role '${user.role}' (${user.mspId}) cannot perform '${action}'. Required role: 'admin' or 'auditor'.`,
        timestamp: now,
        input
      }
    }

    return {
      id,
      allow: false,
      rule: "default_deny",
      reason: `Server Rejection [OPA Default Deny]: Action '${action}' by role '${user.role}' (${user.mspId}) did not satisfy any Zero-Trust access policy rule.`,
      timestamp: now,
      input
    }
  }

  private logDecision(decision: OpaDecision): void {
    this.decisionLogs.unshift(decision)
    if (this.decisionLogs.length > MAX_OPA_LOGS) {
      this.decisionLogs.length = MAX_OPA_LOGS
    }
  }

  public getDecisionLogs(filter?: { onlyRejected?: boolean }): OpaDecision[] {
    if (filter?.onlyRejected) {
      return this.decisionLogs.filter(d => !d.allow)
    }
    return this.decisionLogs
  }

  public clearDecisionLogs(): void {
    this.decisionLogs = []
  }
}

export const opaService = new OpaPolicyService()
