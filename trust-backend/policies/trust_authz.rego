package trust.authz

import rego.v1

# Default deny: Zero-Trust Chain-of-Custody Access Control
default allow := false

# -----------------------------------------------------------------------------
# 1. Organization MSP & Role Parameter Mapping
# -----------------------------------------------------------------------------
role_msp_map := {
  "admin": "AdminOrgMSP",
  "investigator": "PoliceOrgMSP",
  "analyst": "ForensicsOrgMSP",
  "judiciary": "JudiciaryOrgMSP",
  "auditor": "JudiciaryOrgMSP"
}

valid_statuses := {"verified", "pending", "flagged"}

# -----------------------------------------------------------------------------
# 2. User Authorization Status Gates (Approve / Revoke Enforcement)
# -----------------------------------------------------------------------------
user_is_approved if {
  input.user.status == "approved"
}

user_is_pending if {
  input.user.status == "pending"
}

user_is_revoked if {
  input.user.status == "revoked"
}

# Valid W3C DID prefix check
valid_did if {
  startswith(input.user.did, "did:trust:")
}

# -----------------------------------------------------------------------------
# 3. Role-Based & Attribute-Based Access Control (RBAC / ABAC) Rules
# -----------------------------------------------------------------------------

read_actions := {"list_evidence", "inspect_evidence", "view_evidence", "download_evidence", "verify_integrity", "read_audit_log", "export_report"}
admin_actions := {"approve_user", "revoke_user", "manage_users", "manage_firewall", "import_legacy"}
oversight_actions := {"view_policy", "audit_ledger"}

# Rule A: Read / List / Inspect / View / Download / Verify Evidence, read audit log
# Allowed Roles: investigator, analyst, judiciary, auditor, admin (MUST be approved)
# Every view and download is written to the ledger before the file is returned.
allow if {
  user_is_approved
  valid_did
  input.action in read_actions
  input.user.role in {"investigator", "analyst", "judiciary", "auditor", "admin"}
}

# Rule A2: Private case notes (stored only in the Fabric private data collection)
# Allowed Roles: investigator, judiciary, admin. Forensic analysts and auditors see only the hash.
allow if {
  user_is_approved
  valid_did
  input.action == "read_private_details"
  input.user.role in {"investigator", "judiciary", "admin"}
}

# Rule A3: Delegating time-bound case access. Case ownership is checked by the case-access service.
allow if {
  user_is_approved
  valid_did
  input.action == "delegate_case_access"
  input.user.role in {"investigator", "analyst", "admin"}
}

# Rule B: Upload New Digital Evidence & Anchor to Ledger
# Allowed Roles: investigator (PoliceOrgMSP), analyst (ForensicsOrgMSP), admin (AdminOrgMSP)
# Separation of Duties: judiciary and auditor cannot fabricate/upload raw evidence
allow if {
  user_is_approved
  valid_did
  input.action == "upload_evidence"
  input.user.role in {"investigator", "analyst", "admin"}
}

# Rule C: Judicial Verification of Evidence (status == "verified")
# Allowed Roles: ONLY judiciary (JudiciaryOrgMSP) or admin (AdminOrgMSP)
allow if {
  user_is_approved
  valid_did
  input.action == "update_evidence_status"
  input.parameters.status == "verified"
  input.user.role in {"judiciary", "admin"}
}

# Rule D: Forensic Flagging or Pending Reset (status == "flagged" or "pending")
# Allowed Roles: analyst (ForensicsOrgMSP), judiciary (JudiciaryOrgMSP), admin (AdminOrgMSP)
# Separation of Duties: investigator cannot alter status of already-submitted evidence
allow if {
  user_is_approved
  valid_did
  input.action == "update_evidence_status"
  input.parameters.status in {"flagged", "pending"}
  input.user.role in {"analyst", "judiciary", "admin"}
}

# Rule E: Identity administration (approve / revoke DIDs, roles) and firewall management
# Allowed Role: admin (AdminOrgMSP) only. The court reviews evidence; it does not manage accounts.
allow if {
  user_is_approved
  valid_did
  input.action in admin_actions
  input.user.role == "admin"
}

# Rule F: Oversight (policy viewer and dry-run, ledger status, DB-vs-ledger reconciliation)
# Allowed Roles: admin, auditor
allow if {
  user_is_approved
  valid_did
  input.action in oversight_actions
  input.user.role in {"admin", "auditor"}
}

# -----------------------------------------------------------------------------
# 4. Explicit Server Rejection Messages (Reason Generation)
# -----------------------------------------------------------------------------
rejection_reason := msg if {
  user_is_revoked
  msg := sprintf("Server Rejection [OPA Rule: user_not_revoked]: Access Denied. Your cryptographic DID (%s) has been REVOKED by the Administrator. All chain-of-custody permissions are terminated.", [input.user.did])
} else := msg if {
  user_is_pending
  msg := sprintf("Server Rejection [OPA Rule: user_must_be_approved]: Access Denied. Your account (DID: %s, Role: %s) is PENDING Administrator approval. An admin must approve your DID before you can interact with the ledger.", [input.user.did, input.user.role])
} else := msg if {
  not valid_did
  msg := sprintf("Server Rejection [OPA Rule: valid_did]: Malformed Decentralized Identifier (%s). Must conform to W3C method 'did:trust:<identifier>'.", [input.user.did])
} else := msg if {
  input.action == "read_private_details"
  not input.user.role in {"investigator", "judiciary", "admin"}
  msg := sprintf("Server Rejection [OPA Rule: allow_private_details]: Role '%s' (%s) may not read private case notes.", [input.user.role, input.user.mspId])
} else := msg if {
  input.action == "upload_evidence"
  not input.user.role in {"investigator", "analyst", "admin"}
  msg := sprintf("Server Rejection [OPA Rule: allow_upload_evidence]: Role '%s' (%s) is prohibited from uploading evidence. Separation of duties restricts evidence collection to 'investigator' (PoliceOrgMSP) or 'analyst' (ForensicsOrgMSP).", [input.user.role, input.user.mspId])
} else := msg if {
  input.action == "update_evidence_status"
  input.parameters.status == "verified"
  not input.user.role in {"judiciary", "admin"}
  msg := sprintf("Server Rejection [OPA Rule: allow_verify_evidence]: Role '%s' (%s) cannot mark evidence as 'verified'. Judicial verification requires role 'judiciary' (JudiciaryOrgMSP).", [input.user.role, input.user.mspId])
} else := msg if {
  input.action == "update_evidence_status"
  input.parameters.status in {"flagged", "pending"}
  not input.user.role in {"analyst", "judiciary", "admin"}
  msg := sprintf("Server Rejection [OPA Rule: allow_flag_evidence]: Role '%s' (%s) cannot change evidence status to '%s'. Only 'analyst' (ForensicsOrgMSP) or 'judiciary' (JudiciaryOrgMSP) can flag or review evidence.", [input.user.role, input.user.mspId, input.parameters.status])
} else := msg if {
  input.action in oversight_actions
  not input.user.role in {"admin", "auditor"}
  msg := sprintf("Server Rejection [OPA Rule: allow_oversight]: Role '%s' (%s) cannot perform '%s'. Required role: 'admin' or 'auditor'.", [input.user.role, input.user.mspId, input.action])
} else := msg if {
  input.action in admin_actions
  input.user.role != "admin"
  msg := sprintf("Server Rejection [OPA Rule: allow_admin_authorization]: Role '%s' (%s) is not authorized to perform administrative user approval/revocation. Required role: 'admin' (AdminOrgMSP).", [input.user.role, input.user.mspId])
} else := "Server Rejection [OPA Default Deny]: Request parameters did not satisfy any Zero-Trust access policy rule."

