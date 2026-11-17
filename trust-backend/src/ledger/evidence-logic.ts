/**
 * TRUST chain-of-custody contract rules.
 *
 * This file is the single source of truth for what the ledger accepts. It is
 * used in two places:
 *   1. The Hyperledger Fabric chaincode package (trust-chaincode/), which wraps
 *      each function in a fabric-contract-api transaction.
 *   2. The local ledger (local-ledger.ts), which runs the same functions against
 *      a hash-chained, append-only file so development and tests exercise the
 *      exact same rules without a Fabric network.
 *
 * Keep this file free of imports so it can be copied into the chaincode build.
 */

export interface LedgerStub {
  getState(key: string): Promise<Uint8Array | undefined>
  putState(key: string, value: Uint8Array): Promise<void>
  getStateByRange(startKey: string, endKey: string): Promise<Array<{ key: string; value: Uint8Array }>>
  getTxID(): string
  /** ISO-8601 timestamp of the transaction proposal (deterministic across endorsers on Fabric). */
  getTxTimestamp(): string
  /** MSP of the identity that submitted the transaction (Fabric client identity). */
  getCreatorMspId(): string
  /** Transient (off-ledger) proposal input, e.g. private details; never written to blocks. */
  getTransient(key: string): Uint8Array | undefined
  putPrivateData(collection: string, key: string, value: Uint8Array): Promise<void>
  getPrivateData(collection: string, key: string): Promise<Uint8Array | undefined>
  sha256Hex(data: Uint8Array): string
}

/**
 * Private data collection for sensitive case details (original file name, case notes such as
 * witness names). Only member organisations' peers store the plaintext; every peer stores and
 * the block contains only its hash. Members are defined in collections_config.json next to each Fabric network.
 */
export const PRIVATE_COLLECTION = "evidencePrivateDetails"

export interface EvidencePrivateDetails {
  fileName: string
  notes: string
}

export type EvidenceStatus = "pending" | "verified" | "flagged"

export interface EvidenceRecord {
  docType: "evidence"
  id: string
  caseId: string
  fileHash: string
  uploadedByDid: string
  uploaderSignature: string
  orgMspId: string
  status: EvidenceStatus
  /** SHA-256 of the private details JSON held in PRIVATE_COLLECTION ("" if none). */
  privateDetailsHash: string
  createdTxId: string
  lastTxId: string
  createdAt: string
  updatedAt: string
}

export interface AuditRecord {
  docType: "audit"
  logId: string
  targetId: string
  caseId: string
  action: string
  performedByDid: string
  orgMspId: string
  details: string
  txId: string
  timestamp: string
  submitterMspId: string
}

export const EVIDENCE_PREFIX = "EVIDENCE_"
export const AUDIT_PREFIX = "AUDIT_"

const HASH_RE = /^[0-9a-f]{64}$/
const ID_RE = /^[A-Za-z0-9:_\-.]{1,128}$/
const STATUSES: EvidenceStatus[] = ["pending", "verified", "flagged"]

const enc = (o: unknown) => new TextEncoder().encode(JSON.stringify(o))
const dec = <T>(b: Uint8Array) => JSON.parse(new TextDecoder().decode(b)) as T

function requireId(label: string, value: string): void {
  if (typeof value !== "string" || !ID_RE.test(value)) {
    throw new Error(`${label} is missing or malformed`)
  }
}

function requireDid(value: string): void {
  if (typeof value !== "string" || !value.startsWith("did:trust:")) {
    throw new Error("performer DID must use the did:trust: method")
  }
}

async function exists(stub: LedgerStub, key: string): Promise<boolean> {
  const v = await stub.getState(key)
  return !!v && v.length > 0
}

async function writeAudit(
  stub: LedgerStub,
  logId: string,
  targetId: string,
  caseId: string,
  action: string,
  performedByDid: string,
  orgMspId: string,
  details: string
): Promise<AuditRecord> {
  requireId("logId", logId)
  requireId("caseId", caseId)
  requireDid(performedByDid)
  if (!action || action.length > 64) throw new Error("action is missing or too long")
  const key = AUDIT_PREFIX + logId
  if (await exists(stub, key)) throw new Error(`audit record ${logId} already exists`)
  const record: AuditRecord = {
    docType: "audit",
    logId,
    targetId,
    caseId,
    action,
    performedByDid,
    orgMspId,
    details: details || "",
    txId: stub.getTxID(),
    timestamp: stub.getTxTimestamp(),
    submitterMspId: stub.getCreatorMspId()
  }
  await stub.putState(key, enc(record))
  return record
}

/** Anchors a new evidence item and its "uploaded" audit event in one transaction. */
export async function CreateEvidence(
  stub: LedgerStub,
  id: string,
  caseId: string,
  fileHash: string,
  uploadedByDid: string,
  uploaderSignature: string,
  orgMspId: string,
  logId: string
): Promise<{ evidence: EvidenceRecord; audit: AuditRecord }> {
  requireId("evidence id", id)
  requireId("caseId", caseId)
  requireDid(uploadedByDid)
  if (typeof fileHash !== "string" || !HASH_RE.test(fileHash)) {
    throw new Error("fileHash must be a 64-character lowercase hex SHA-256 digest")
  }
  if (typeof uploaderSignature !== "string" || !/^[0-9a-f]{128}$/.test(uploaderSignature)) {
    throw new Error("uploaderSignature must be a 64-byte Ed25519 signature in hex")
  }
  const key = EVIDENCE_PREFIX + id
  if (await exists(stub, key)) throw new Error(`evidence ${id} already exists`)

  let privateDetailsHash = ""
  const priv = stub.getTransient("private")
  if (priv && priv.length) {
    let parsed: EvidencePrivateDetails
    try {
      parsed = JSON.parse(new TextDecoder().decode(priv))
    } catch {
      throw new Error("private details must be JSON")
    }
    if (typeof parsed.fileName !== "string" || typeof parsed.notes !== "string") throw new Error("private details must be {fileName, notes} strings")
    const bytes = enc({ fileName: parsed.fileName, notes: parsed.notes })
    await stub.putPrivateData(PRIVATE_COLLECTION, key, bytes)
    privateDetailsHash = stub.sha256Hex(bytes)
  }

  const now = stub.getTxTimestamp()
  const evidence: EvidenceRecord = {
    docType: "evidence",
    id,
    caseId,
    fileHash,
    uploadedByDid,
    uploaderSignature,
    orgMspId,
    status: "pending",
    privateDetailsHash,
    createdTxId: stub.getTxID(),
    lastTxId: stub.getTxID(),
    createdAt: now,
    updatedAt: now
  }
  await stub.putState(key, enc(evidence))
  const audit = await writeAudit(stub, logId, id, caseId, "uploaded", uploadedByDid, orgMspId, fileHash)
  return { evidence, audit }
}

/** Changes the status of an evidence item and records who did it. */
export async function UpdateEvidenceStatus(
  stub: LedgerStub,
  id: string,
  newStatus: string,
  performedByDid: string,
  orgMspId: string,
  logId: string,
  signature: string
): Promise<{ evidence: EvidenceRecord; audit: AuditRecord }> {
  requireId("evidence id", id)
  if (!STATUSES.includes(newStatus as EvidenceStatus)) {
    throw new Error(`status must be one of ${STATUSES.join(", ")}`)
  }
  const raw = await stub.getState(EVIDENCE_PREFIX + id)
  if (!raw || raw.length === 0) throw new Error(`evidence ${id} does not exist`)
  const evidence = dec<EvidenceRecord>(raw)
  if (evidence.status === newStatus) throw new Error(`evidence ${id} is already ${newStatus}`)

  const previous = evidence.status
  evidence.status = newStatus as EvidenceStatus
  evidence.lastTxId = stub.getTxID()
  evidence.updatedAt = stub.getTxTimestamp()
  await stub.putState(EVIDENCE_PREFIX + id, enc(evidence))
  const audit = await writeAudit(
    stub, logId, id, evidence.caseId, `status_${newStatus}`, performedByDid, orgMspId,
    JSON.stringify({ from: previous, to: newStatus, signature })
  )
  return { evidence, audit }
}

/** Records any other custody or identity event (view, download, approval, revocation, integrity check). */
export async function RecordAuditAccess(
  stub: LedgerStub,
  logId: string,
  targetId: string,
  caseId: string,
  action: string,
  performedByDid: string,
  orgMspId: string,
  details: string
): Promise<AuditRecord> {
  if (targetId.startsWith("did:trust:")) {
    // identity events target a DID
  } else {
    requireId("targetId", targetId)
  }
  return writeAudit(stub, logId, targetId, caseId, action, performedByDid, orgMspId, details)
}

export async function ReadEvidence(stub: LedgerStub, id: string): Promise<EvidenceRecord | null> {
  const raw = await stub.getState(EVIDENCE_PREFIX + id)
  return raw && raw.length ? dec<EvidenceRecord>(raw) : null
}

/** Readable only on peers of member organisations; returns null elsewhere or if none was stored. */
export async function ReadEvidencePrivate(stub: LedgerStub, id: string): Promise<(EvidencePrivateDetails & { hashMatches: boolean }) | null> {
  const pub = await ReadEvidence(stub, id)
  if (!pub || !pub.privateDetailsHash) return null
  const raw = await stub.getPrivateData(PRIVATE_COLLECTION, EVIDENCE_PREFIX + id)
  if (!raw || !raw.length) return null
  return { ...dec<EvidencePrivateDetails>(raw), hashMatches: stub.sha256Hex(raw) === pub.privateDetailsHash }
}

export async function ReadAudit(stub: LedgerStub, logId: string): Promise<AuditRecord | null> {
  const raw = await stub.getState(AUDIT_PREFIX + logId)
  return raw && raw.length ? dec<AuditRecord>(raw) : null
}

export async function ListAudit(stub: LedgerStub): Promise<AuditRecord[]> {
  const rows = await stub.getStateByRange(AUDIT_PREFIX, AUDIT_PREFIX + "￿")
  return rows.map(r => dec<AuditRecord>(r.value))
}

export async function ListEvidence(stub: LedgerStub): Promise<EvidenceRecord[]> {
  const rows = await stub.getStateByRange(EVIDENCE_PREFIX, EVIDENCE_PREFIX + "￿")
  return rows.map(r => dec<EvidenceRecord>(r.value))
}

export const SUBMIT_FUNCTIONS = {
  CreateEvidence,
  UpdateEvidenceStatus,
  RecordAuditAccess
} as const

export const EVALUATE_FUNCTIONS = {
  ReadEvidence,
  ReadEvidencePrivate,
  ReadAudit,
  ListAudit,
  ListEvidence
} as const
