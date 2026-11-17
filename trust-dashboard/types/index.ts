export type EvidenceStatus = "verified" | "pending" | "flagged"

export type Evidence = {
  id: string
  name: string
  hash: string
  uploadedBy: string
  timestamp: string
  status: EvidenceStatus
  fileType: string
  caseId: string
  fileSize: number
  fileUrl?: string | null
  uploaderSignature?: string
  encryption?: string
  txHash?: string
  blockNumber?: number | null
}

export type AuditAction =
  | "uploaded"
  | "accessed"
  | "viewed"
  | "downloaded"
  | "integrity_checked"
  | "transferred"
  | "verified"
  | "flagged"
  | "status_updated"
  | "user_approved"
  | "user_revoked"
  | "user_pending"
  | "did_registered_pending"
  | "did_registered_approved"

export type AuditEntry = {
  id: string
  evidenceId: string
  caseId: string
  action: AuditAction | string
  performedBy: string
  timestamp: string
  txHash: string
  blockNumber?: number | null
  details?: string | null
}

export interface DIDDocument {
  "@context": string[]
  id: string
  controller: string
  verificationMethod: Array<{
    id: string
    type: string
    controller: string
    publicKeyPem: string
    publicKeyHex: string
    fingerprint: string
  }>
  authentication: string[]
  assertionMethod: string[]
  service: Array<{
    id: string
    type: string
    serviceEndpoint: string
  }>
  metadata: {
    role: string
    mspId: string
    status: "approved" | "pending" | "revoked"
    created: string
    updated: string
    ledgerTxHash?: string
  }
}

export interface UserProfile {
  uid: string
  email: string
  displayName: string
  role: "admin" | "investigator" | "analyst" | "judiciary" | "auditor"
  did: string
  mspId: string
  status: "approved" | "pending" | "revoked"
  publicKeyHex?: string
  publicKeyPem?: string
  fingerprint?: string
  didDocument?: DIDDocument
  createdAt?: string
  updatedAt?: string
  authorizedBy?: string
  txHash?: string
}