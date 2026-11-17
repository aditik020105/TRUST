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
}

export type AuditAction = "uploaded" | "accessed" | "transferred" | "verified" | "flagged" | "status_updated"

export type AuditEntry = {
  id: string
  evidenceId: string
  caseId: string
  action: AuditAction
  performedBy: string
  timestamp: string
  txHash: string
}

export type ApiResponse<T> = {
  success: boolean
  data?: T
  error?: string
}