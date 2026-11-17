import { Response } from "express"
import { v4 as uuidv4 } from "uuid"
import crypto from "crypto"
import { supabase, blobToBuffer, EVIDENCE_BUCKET } from "../lib/supabase"
import { AuthRequest } from "../middleware/auth.middleware"
import { hyperledgerService, LedgerUnavailableError } from "../services/hyperledger.service"
import { verifyWithDocument, signingPayloads } from "../services/did.service"
import { encryptEvidence, decryptEvidence, ENCRYPTION_ALG } from "../services/encryption.service"
import { userService } from "../services/user.service"
import { caseAccessService } from "../services/case-access.service"
import { insertAuditRow } from "../services/audit-row.service"
import { ReportBody, sealReport, renderReportPdf } from "../services/report.service"

const CASE_ID_RE = /^[A-Za-z0-9][A-Za-z0-9_\-.]{0,63}$/
const VALID_STATUSES = ["verified", "pending", "flagged"]

export function mapEvidence(e: any) {
  return {
    id: e.id,
    name: e.name,
    hash: e.hash,
    uploadedBy: e.uploaded_by,
    uploaderSignature: e.uploader_signature,
    timestamp: e.timestamp,
    status: e.status,
    fileType: e.file_type,
    caseId: e.case_id,
    fileSize: e.file_size,
    encryption: e.encryption,
    txHash: e.tx_hash,
    blockNumber: e.block_number
  }
}

const newLogId = () => `LOG-${uuidv4().slice(0, 8).toUpperCase()}`

/** Maps ledger failures to HTTP responses. Returns true if it handled the error. */
function ledgerError(res: Response, err: any): boolean {
  if (err instanceof LedgerUnavailableError) {
    res.status(502).json({ success: false, code: "LEDGER_UNAVAILABLE", error: `${err.message}. No change was made.` })
    return true
  }
  if (err?.name === "LedgerRuleError") {
    res.status(409).json({ success: false, code: "LEDGER_REJECTED", error: err.message })
    return true
  }
  return false
}

async function loadEvidenceRow(id: string) {
  const { data, error } = await supabase.from("evidence").select("*").eq("id", id).maybeSingle()
  if (error) throw new Error(error.message)
  return data
}

// GET /api/evidence?caseId=&status=
export async function getAllEvidence(req: AuthRequest, res: Response) {
  const { caseId, status } = req.query
  let query = supabase.from("evidence").select("*")
  if (caseId) query = query.eq("case_id", String(caseId))
  if (status) query = query.eq("status", String(status))
  const { data, error } = await query.order("timestamp", { ascending: false })
  if (error) return res.status(500).json({ success: false, error: error.message })
  const visible = await caseAccessService.accessibleCases(req.user!)
  const rows = (data || []).filter((r: any) => !visible || visible.has(r.case_id))
  res.json({ success: true, data: rows.map(mapEvidence) })
}

// GET /api/evidence/:id  (metadata only; file access goes through /view or /download)
export async function getEvidenceById(req: AuthRequest, res: Response) {
  const row = await loadEvidenceRow(String(req.params.id))
  if (!row) return res.status(404).json({ success: false, error: "Evidence not found" })
  await caseAccessService.assert(req.user!, row.case_id, "read")
  res.json({ success: true, data: mapEvidence(row) })
}

/**
 * POST /api/evidence/upload  multipart: file, caseId, signature
 * signature = Ed25519 signature (hex) by the caller's DID key over "TRUST-UPLOAD|<caseId>|<sha256>".
 * Order: verify signature -> encrypt -> store blob -> commit to ledger -> insert DB rows.
 */
export async function uploadEvidence(req: AuthRequest, res: Response) {
  const caseId = String(req.body?.caseId || "").trim()
  const signature = String(req.body?.signature || "").trim().toLowerCase()
  const notes = String(req.body?.notes || "").slice(0, 4000)
  const file = req.file
  const user = req.user!

  if (!caseId || !CASE_ID_RE.test(caseId)) {
    return res.status(400).json({ success: false, error: "caseId is required (letters, digits, - _ . ; max 64 chars)" })
  }
  if (!file || !file.buffer?.length) return res.status(400).json({ success: false, error: "file is required" })
  if (!signature) return res.status(400).json({ success: false, error: "signature is required: sign the upload with your DID key" })

  await caseAccessService.assert(user, caseId, "contribute")

  const fileHash = crypto.createHash("sha256").update(file.buffer).digest("hex")
  const proof = verifyWithDocument(req.account!.didDocument, signingPayloads.upload(caseId, fileHash), signature)
  if (!proof.verified) {
    return res.status(400).json({
      success: false,
      code: "SIGNATURE_INVALID",
      error: `Upload signature rejected: ${proof.reason}. The server computed SHA-256 ${fileHash}; sign "TRUST-UPLOAD|${caseId}|${fileHash}".`
    })
  }

  const evidenceId = `EV-${uuidv4().slice(0, 8).toUpperCase()}`
  const logId = newLogId()
  const storagePath = `cases/${caseId}/${evidenceId}.enc`
  const encrypted = encryptEvidence(file.buffer, evidenceId)

  const { error: storageError } = await supabase.storage.from(EVIDENCE_BUCKET).upload(storagePath, encrypted, {
    contentType: "application/octet-stream",
    upsert: false
  })
  if (storageError) return res.status(500).json({ success: false, error: `Storage upload failed: ${storageError.message}` })

  let ledger
  try {
    await caseAccessService.openCaseIfNew(caseId, user)
    ledger = await hyperledgerService.createEvidence({
      id: evidenceId, caseId, fileHash, uploadedByDid: user.did, signatureHex: signature, mspId: user.mspId, logId,
      // Case notes (e.g. witness names) are never stored in the database: only member organisations'
      // peers hold them, in the private data collection; the block holds their hash.
      privateDetails: { fileName: file.originalname.slice(0, 255), notes }
    })
  } catch (err) {
    await supabase.storage.from(EVIDENCE_BUCKET).remove([storagePath]).catch(() => undefined)
    if (ledgerError(res, err)) return
    throw err
  }

  const row = {
    id: evidenceId,
    name: file.originalname.slice(0, 255),
    hash: fileHash,
    uploaded_by: user.did,
    uploader_signature: signature,
    timestamp: ledger.result.evidence.createdAt,
    status: "pending",
    file_type: file.mimetype || "application/octet-stream",
    case_id: caseId,
    file_size: file.size,
    file_url: storagePath,
    encryption: ENCRYPTION_ALG,
    tx_hash: ledger.txId,
    block_number: ledger.blockNumber
  }
  const { error } = await supabase.from("evidence").insert(row)
  if (error) {
    console.error(`[evidence] ${evidenceId} anchored in tx ${ledger.txId} but DB insert failed: ${error.message}`)
    return res.status(500).json({ success: false, error: `Anchored on ledger (tx ${ledger.txId}) but database insert failed: ${error.message}`, txHash: ledger.txId })
  }
  await insertAuditRow({
    id: logId, evidence_id: evidenceId, case_id: caseId, action: "uploaded", performed_by: user.did,
    tx_hash: ledger.txId, block_number: ledger.blockNumber, details: fileHash
  })

  res.status(201).json({
    success: true,
    data: mapEvidence(row),
    txHash: ledger.txId,
    blockNumber: ledger.blockNumber,
    didSignature: signature,
    signatureCheck: proof
  })
}

/**
 * PATCH /api/evidence/:id/status { status, signature }
 * signature = Ed25519 signature over "TRUST-STATUS|<id>|<status>". Ledger first, then DB.
 */
export async function updateEvidenceStatus(req: AuthRequest, res: Response) {
  const id = String(req.params.id)
  const status = req.body?.status
  const signature = String(req.body?.signature || "").trim().toLowerCase()
  const user = req.user!

  if (!status || !VALID_STATUSES.includes(status)) return res.status(400).json({ success: false, error: "Invalid status value" })
  if (!signature) return res.status(400).json({ success: false, error: "signature is required: sign the status change with your DID key" })

  const row = await loadEvidenceRow(id)
  if (!row) return res.status(404).json({ success: false, error: "Evidence not found" })
  await caseAccessService.assert(req.user!, row.case_id, "read")

  const proof = verifyWithDocument(req.account!.didDocument, signingPayloads.status(id, status), signature)
  if (!proof.verified) return res.status(400).json({ success: false, code: "SIGNATURE_INVALID", error: `Status signature rejected: ${proof.reason}` })

  const logId = newLogId()
  let ledger
  try {
    ledger = await hyperledgerService.updateEvidenceStatus({ id, status, performedByDid: user.did, mspId: user.mspId, logId, signatureHex: signature })
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }

  const { data, error } = await supabase.from("evidence").update({ status }).eq("id", id).select().single()
  if (error || !data) {
    console.error(`[evidence] status of ${id} committed in tx ${ledger.txId} but DB update failed: ${error?.message}`)
    return res.status(500).json({ success: false, error: "Committed on ledger but database update failed", txHash: ledger.txId })
  }
  await insertAuditRow({
    id: logId, evidence_id: id, case_id: row.case_id, action: `status_${status}`, performed_by: user.did,
    tx_hash: ledger.txId, block_number: ledger.blockNumber, details: ledger.result.audit.details
  })

  res.json({ success: true, data: mapEvidence(data), txHash: ledger.txId, blockNumber: ledger.blockNumber })
}

/**
 * Shared by /view and /download: the access is committed to the ledger and the audit table
 * BEFORE any byte of the file is read. If the ledger write fails, the file is not released.
 */
async function releaseFile(req: AuthRequest, res: Response, mode: "accessed" | "viewed" | "downloaded") {
  const id = String(req.params.id)
  const row = await loadEvidenceRow(id)
  if (!row) return res.status(404).json({ success: false, error: "Evidence not found" })
  await caseAccessService.assert(req.user!, row.case_id, "read")
  if (!row.file_url) return res.status(404).json({ success: false, error: "No stored file for this evidence record" })

  const logId = newLogId()
  let ledger
  try {
    ledger = await hyperledgerService.recordAudit({
      logId, targetId: id, caseId: row.case_id, action: mode, performedByDid: req.user!.did, mspId: req.user!.mspId
    })
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }
  await insertAuditRow({ id: logId, evidence_id: id, case_id: row.case_id, action: mode, performed_by: req.user!.did, tx_hash: ledger.txId, block_number: ledger.blockNumber })

  const { data: blob, error } = await supabase.storage.from(EVIDENCE_BUCKET).download(row.file_url)
  if (error || !blob) return res.status(404).json({ success: false, error: `Stored file missing: ${error?.message || "not found"}` })

  let plaintext: Buffer
  try {
    plaintext = decryptEvidence(await blobToBuffer(blob), id)
  } catch {
    return res.status(409).json({ success: false, code: "INTEGRITY_FAILURE", error: "Stored ciphertext failed AES-GCM authentication: the file was altered or swapped" })
  }
  const actualHash = crypto.createHash("sha256").update(plaintext).digest("hex")
  if (actualHash !== row.hash) {
    return res.status(409).json({ success: false, code: "INTEGRITY_FAILURE", error: "Decrypted file hash does not match the recorded hash" })
  }

  const safeName = String(row.name || id).replace(/[^\w.\- ]/g, "_")
  res.setHeader("Content-Type", row.file_type || "application/octet-stream")
  res.setHeader("Content-Disposition", `${mode === "downloaded" ? "attachment" : "inline"}; filename="${safeName}"`)
  res.setHeader("X-Content-Type-Options", "nosniff")
  res.setHeader("Cache-Control", "no-store")
  res.setHeader("Content-Security-Policy", "sandbox; default-src 'none'; img-src 'self' data: blob:; media-src 'self' blob:; style-src 'unsafe-inline'")
  res.setHeader("X-Evidence-SHA256", actualHash)
  res.setHeader("X-Ledger-Tx", ledger.txId)
  res.send(plaintext)
}

// GET /api/evidence/:id/view
export function viewEvidenceFile(req: AuthRequest, res: Response) {
  return releaseFile(req, res, "accessed")
}

// GET /api/evidence/:id/download (Disabled to prevent untracked local tampering)
export function downloadEvidenceFile(req: AuthRequest, res: Response) {
  return res.status(403).json({
    success: false,
    code: "DOWNLOAD_DISABLED",
    error: "Direct file downloads are disabled to prevent offline tampering. Use in-browser viewing (/view) instead."
  })
}

// GET /api/evidence/:id/private  (case notes from the private data collection)
export async function getPrivateDetails(req: AuthRequest, res: Response) {
  const id = String(req.params.id)
  const row = await loadEvidenceRow(id)
  if (!row) return res.status(404).json({ success: false, error: "Evidence not found" })
  await caseAccessService.assert(req.user!, row.case_id, "read")
  const details = await hyperledgerService.readEvidencePrivate(id, req.user!.mspId)
  if (!details) {
    return res.status(403).json({
      success: false,
      code: "NOT_A_COLLECTION_MEMBER",
      error: `Organisation ${req.user!.mspId} is not a member of the private data collection, or no private details were stored`
    })
  }
  const logId = newLogId()
  let ledger
  try {
    ledger = await hyperledgerService.recordAudit({ logId, targetId: id, caseId: row.case_id, action: "private_details_read", performedByDid: req.user!.did, mspId: req.user!.mspId })
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }
  await insertAuditRow({ id: logId, evidence_id: id, case_id: row.case_id, action: "private_details_read", performed_by: req.user!.did, tx_hash: ledger.txId, block_number: ledger.blockNumber })
  res.json({ success: true, data: details })
}

type Check = { name: string; ok: boolean; detail: string }

/**
 * GET /api/evidence/:id/verify
 * Recomputes the file hash and compares it with the ledger record itself (not the DB copy),
 * checks the uploader's signature, and matches every audit row against its ledger transaction.
 * The check is itself recorded as an "integrity_checked" custody event.
 */
/** Every integrity check for one evidence item, compared against the ledger record itself. */
async function computeVerification(row: any, id: string, user: { did: string; mspId: string }) {
  const checks: Check[] = []
  let ledgerRec
  try {
    ledgerRec = await hyperledgerService.readEvidence(id)
  } catch (err: any) {
    throw new LedgerUnavailableError(`Cannot read ledger: ${err.message}`, err)
  }
  checks.push({ name: "Anchored on ledger", ok: !!ledgerRec, detail: ledgerRec ? `created in tx ${ledgerRec.createdTxId}` : "no ledger record for this evidence ID" })

  if (ledgerRec) {
    const diffs: string[] = []
    if (row.hash !== ledgerRec.fileHash) diffs.push("hash")
    if (row.case_id !== ledgerRec.caseId) diffs.push("case ID")
    if (row.uploaded_by !== ledgerRec.uploadedByDid) diffs.push("uploader")
    if (row.status !== ledgerRec.status) diffs.push(`status (db=${row.status}, ledger=${ledgerRec.status})`)
    if (row.tx_hash !== ledgerRec.createdTxId) diffs.push("creation tx")
    checks.push({ name: "Database row matches ledger", ok: diffs.length === 0, detail: diffs.length ? `mismatch: ${diffs.join(", ")}` : "hash, case, uploader, status and tx agree" })
  }

  let fileHash: string | null = null
  if (row.file_url) {
    const { data: blob, error } = await supabase.storage.from(EVIDENCE_BUCKET).download(row.file_url)
    if (error || !blob) {
      checks.push({ name: "Stored file present", ok: false, detail: error?.message || "missing" })
    } else {
      try {
        const plain = decryptEvidence(await blobToBuffer(blob), id)
        checks.push({ name: "Ciphertext authentic (AES-256-GCM tag)", ok: true, detail: "decrypted and authenticated" })
        fileHash = crypto.createHash("sha256").update(plain).digest("hex")
      } catch {
        checks.push({ name: "Ciphertext authentic (AES-256-GCM tag)", ok: false, detail: "authentication failed: stored file altered or swapped" })
      }
    }
  } else {
    checks.push({ name: "Stored file present", ok: false, detail: "no storage path recorded" })
  }

  if (fileHash && ledgerRec) {
    checks.push({
      name: "File SHA-256 matches ledger",
      ok: fileHash === ledgerRec.fileHash,
      detail: fileHash === ledgerRec.fileHash ? fileHash : `file ${fileHash} vs ledger ${ledgerRec.fileHash}`
    })
  }

  if (ledgerRec) {
    // resolveDid also finds DIDs retired by key recovery, so older uploads still verify
    const uploader = await userService.resolveDid(ledgerRec.uploadedByDid)
    const sig = verifyWithDocument(uploader?.document, signingPayloads.upload(ledgerRec.caseId, ledgerRec.fileHash), ledgerRec.uploaderSignature)
    checks.push({ name: "Uploader signature valid", ok: sig.verified, detail: sig.reason })
  }

  if (ledgerRec?.privateDetailsHash) {
    const priv = await hyperledgerService.readEvidencePrivate(id, user.mspId).catch(() => null)
    checks.push(priv
      ? { name: "Private case notes match their on-chain hash", ok: priv.hashMatches, detail: priv.hashMatches ? ledgerRec.privateDetailsHash : "private data differs from the hash in the block" }
      : { name: "Private case notes match their on-chain hash", ok: true, detail: `held only by member organisations; hash ${ledgerRec.privateDetailsHash.slice(0, 16)}… is on-chain` })
  }

  let { data: auditRows } = await supabase.from("audit_log").select("*").eq("evidence_id", id).order("timestamp", { ascending: true })
  const ledgerAudits = (await hyperledgerService.listAudit()).filter(a => a.targetId === id)
  const ledgerById = new Map(ledgerAudits.map(a => [a.logId, a]))
  let dbIds = new Set((auditRows || []).map((r: any) => r.id))
  let missingInDb = ledgerAudits.filter(a => !dbIds.has(a.logId))

  // Self-healing: if events exist on the immutable blockchain ledger but were missed by the DB, reconcile them from the ledger
  if (missingInDb.length > 0) {
    for (const m of missingInDb) {
      await insertAuditRow({
        id: m.logId,
        evidence_id: m.targetId,
        case_id: m.caseId,
        action: m.action,
        performed_by: m.performedByDid,
        tx_hash: m.txId,
        timestamp: m.timestamp,
        details: m.details
      }).catch(() => undefined)
    }
    const refetched = await supabase.from("audit_log").select("*").eq("evidence_id", id).order("timestamp", { ascending: true })
    if (refetched.data) {
      auditRows = refetched.data
      dbIds = new Set(auditRows.map((r: any) => r.id))
      missingInDb = ledgerAudits.filter(a => !dbIds.has(a.logId))
    }
  }

  const timeline = (auditRows || []).map((r: any) => {
    const l = ledgerById.get(r.id)
    const match = !!l && l.txId === r.tx_hash && l.action === r.action && l.performedByDid === r.performed_by
    return {
      id: r.id, action: r.action, performedBy: r.performed_by, timestamp: r.timestamp, txHash: r.tx_hash, blockNumber: r.block_number,
      ledgerMatch: match, ledgerTimestamp: l?.timestamp || null
    }
  })
  const badRows = timeline.filter((t: any) => !t.ledgerMatch)
  checks.push({
    name: "Every audit row matches its ledger transaction",
    ok: badRows.length === 0 && missingInDb.length === 0,
    detail: `${timeline.length - badRows.length}/${timeline.length} rows match` +
      (badRows.length ? `; unmatched: ${badRows.map((b: any) => b.id).join(", ")}` : "") +
      (missingInDb.length ? `; ledger events missing from DB: ${missingInDb.map(m => m.logId).join(", ")}` : "")
  })

  const chain = await hyperledgerService.verifyChain()
  if (chain) checks.push({ name: "Ledger hash chain intact", ok: chain.ok, detail: chain.ok ? `${chain.height} blocks verified` : chain.reason || "broken" })

  const verified = checks.every(c => c.ok)
  return { verified, checks, ledgerRec, timeline }
}

export async function verifyEvidence(req: AuthRequest, res: Response) {
  const id = String(req.params.id)
  const row = await loadEvidenceRow(id)
  if (!row) return res.status(404).json({ success: false, error: "Evidence not found" })
  await caseAccessService.assert(req.user!, row.case_id, "read")

  let result
  try {
    result = await computeVerification(row, id, req.user!)
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }
  const { verified, checks, ledgerRec, timeline } = result

  // Record the verification itself; fail closed like any other access.
  const logId = newLogId()
  let ledger
  try {
    ledger = await hyperledgerService.recordAudit({
      logId, targetId: id, caseId: row.case_id, action: "integrity_checked", performedByDid: req.user!.did, mspId: req.user!.mspId,
      details: JSON.stringify({ verified, failed: checks.filter(c => !c.ok).map(c => c.name) })
    })
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }
  await insertAuditRow({
    id: logId, evidence_id: id, case_id: row.case_id, action: "integrity_checked", performed_by: req.user!.did,
    tx_hash: ledger.txId, block_number: ledger.blockNumber, details: verified ? "verified" : "FAILED"
  })

  res.json({
    success: true,
    data: {
      evidenceId: id,
      verified,
      checkedAt: new Date().toISOString(),
      checks,
      ledgerRecord: ledgerRec,
      timeline,
      verificationTx: ledger.txId
    }
  })
}

/**
 * GET /api/evidence/:id/report?format=pdf|json
 * Courtroom export: verification results, ledger anchor, full custody timeline, uploader DID
 * document. The report hash is committed to the ledger ("report_exported") before release.
 */
export async function exportCourtReport(req: AuthRequest, res: Response) {
  const id = String(req.params.id)
  const format = String(req.query.format || "pdf").toLowerCase()
  if (!["pdf", "json"].includes(format)) return res.status(400).json({ success: false, error: "format must be pdf or json" })
  const row = await loadEvidenceRow(id)
  if (!row) return res.status(404).json({ success: false, error: "Evidence not found" })
  await caseAccessService.assert(req.user!, row.case_id, "read")

  let v
  try {
    v = await computeVerification(row, id, req.user!)
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }
  const info = await hyperledgerService.info()
  const uploader = await userService.resolveDid(row.uploaded_by)
  const body: ReportBody = {
    format: "trust-custody-report/1",
    generatedAt: new Date().toISOString(),
    generatedBy: { did: req.user!.did, role: req.user!.role, mspId: req.user!.mspId },
    evidence: mapEvidence(row),
    verdict: { verified: v.verified, failedChecks: v.checks.filter(c => !c.ok).map(c => c.name) },
    checks: v.checks,
    ledgerRecord: v.ledgerRec,
    ledger: { mode: info.mode, channel: info.channel, chaincode: info.chaincode },
    custodyTimeline: v.timeline,
    uploaderDidDocument: uploader?.document || null
  }
  const seal = sealReport(body)

  const logId = newLogId()
  let ledger
  try {
    ledger = await hyperledgerService.recordAudit({
      logId, targetId: id, caseId: row.case_id, action: "report_exported", performedByDid: req.user!.did, mspId: req.user!.mspId,
      details: JSON.stringify({ reportHash: seal.reportHash, format, verified: v.verified })
    })
  } catch (err) {
    if (ledgerError(res, err)) return
    throw err
  }
  await insertAuditRow({
    id: logId, evidence_id: id, case_id: row.case_id, action: "report_exported", performed_by: req.user!.did,
    tx_hash: ledger.txId, block_number: ledger.blockNumber, details: seal.reportHash
  })

  const fullSeal = { ...seal, exportTx: ledger.txId, exportBlock: ledger.blockNumber }
  res.setHeader("Cache-Control", "no-store")
  res.setHeader("X-Report-SHA256", seal.reportHash)
  res.setHeader("X-Ledger-Tx", ledger.txId)
  if (format === "json") {
    res.setHeader("Content-Disposition", `attachment; filename="custody-report-${id}.json"`)
    return res.json({ report: body, seal: fullSeal })
  }
  const pdf = await renderReportPdf(body, fullSeal)
  res.setHeader("Content-Type", "application/pdf")
  res.setHeader("Content-Disposition", `attachment; filename="custody-report-${id}.pdf"`)
  res.send(pdf)
}

// GET /api/cases/:caseId/custody  (machine-readable export for case-management systems)
export async function exportCaseCustody(req: AuthRequest, res: Response) {
  const caseId = String(req.params.caseId)
  await caseAccessService.assert(req.user!, caseId, "read")
  const { data: evidence } = await supabase.from("evidence").select("*").eq("case_id", caseId).order("timestamp", { ascending: true })
  const { data: events } = await supabase.from("audit_log").select("*").eq("case_id", caseId).order("timestamp", { ascending: true })
  const ledgerAudits = new Map((await hyperledgerService.listAudit()).filter(a => a.caseId === caseId).map(a => [a.logId, a]))
  res.json({
    success: true,
    data: {
      format: "trust-case-custody/1",
      caseId,
      exportedAt: new Date().toISOString(),
      evidence: (evidence || []).map(mapEvidence),
      events: (events || []).map((e: any) => {
        const l = ledgerAudits.get(e.id)
        return {
          id: e.id, evidenceId: e.evidence_id, action: e.action, performedBy: e.performed_by, timestamp: e.timestamp,
          txHash: e.tx_hash, blockNumber: e.block_number, details: e.details,
          ledgerMatch: !!l && l.txId === e.tx_hash && l.action === e.action && l.performedByDid === e.performed_by
        }
      })
    }
  })
}
