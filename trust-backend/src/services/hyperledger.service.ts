import path from "path"
import { Ledger, LedgerTxResult, ChainVerification, LedgerInfo, LedgerCallOptions } from "../ledger/types"
import { LocalLedger } from "../ledger/local-ledger"
import type { EvidenceRecord, AuditRecord, EvidencePrivateDetails } from "../ledger/evidence-logic"

export type { EvidenceRecord, AuditRecord, EvidencePrivateDetails }

export class LedgerUnavailableError extends Error {
  constructor(message: string, public cause?: unknown) {
    super(message)
    this.name = "LedgerUnavailableError"
  }
}

function createLedger(): Ledger {
  const mode = (process.env.LEDGER_MODE || "local").toLowerCase()
  if (mode === "fabric") {
    // eslint-disable-next-line @typescript-eslint/no-var-requires
    const { FabricLedger } = require("../ledger/fabric-ledger")
    return new FabricLedger()
  }
  const dataDir = process.env.DATA_DIR || path.join(process.cwd(), "data")
  return new LocalLedger(process.env.LEDGER_FILE || path.join(dataDir, "ledger.json"))
}

/**
 * Facade over the configured ledger (local hash-chained file or Hyperledger Fabric).
 * Every submit either commits and returns the real transaction ID and block number,
 * or throws. Callers must treat a throw as "the event did not happen".
 */
export class HyperledgerFabricService {
  private ledger: Ledger = createLedger()

  /** For tests: swap in a fresh ledger (e.g. after changing DATA_DIR). */
  reset(ledger?: Ledger): void {
    this.ledger = ledger || createLedger()
  }

  private async submit<T>(fn: Parameters<Ledger["submit"]>[0], args: string[], opts?: LedgerCallOptions): Promise<LedgerTxResult<T>> {
    try {
      return await this.ledger.submit<T>(fn, args, opts)
    } catch (err: any) {
      const msg = err?.message || String(err)
      // Contract rule violations are client errors; everything else means the ledger is unreachable.
      if (/already exists|does not exist|must be|malformed|is missing|already (pending|verified|flagged)|too long/.test(msg)) {
        const e = new Error(msg)
        e.name = "LedgerRuleError"
        throw e
      }
      throw new LedgerUnavailableError(`Ledger commit failed: ${msg}`, err)
    }
  }

  /** privateDetails go to the private data collection via transient data; only their hash is on-chain. */
  createEvidence(p: {
    id: string; caseId: string; fileHash: string; uploadedByDid: string; signatureHex: string; mspId: string; logId: string
    privateDetails?: EvidencePrivateDetails
  }) {
    const transient = p.privateDetails ? { private: Buffer.from(JSON.stringify(p.privateDetails)) } : undefined
    return this.submit<{ evidence: EvidenceRecord; audit: AuditRecord }>("CreateEvidence", [
      p.id, p.caseId, p.fileHash, p.uploadedByDid, p.signatureHex, p.mspId, p.logId
    ], { mspId: p.mspId, transient })
  }

  /** Returns null when the caller's organisation is not a member of the private collection. */
  async readEvidencePrivate(id: string, mspId: string): Promise<(EvidencePrivateDetails & { hashMatches: boolean }) | null> {
    try {
      return await this.ledger.evaluate("ReadEvidencePrivate", [id], { mspId })
    } catch (err: any) {
      if (/access|permission|not authorized|private/i.test(err?.message || "")) return null
      throw err
    }
  }

  updateEvidenceStatus(p: {
    id: string; status: string; performedByDid: string; mspId: string; logId: string; signatureHex: string
  }) {
    return this.submit<{ evidence: EvidenceRecord; audit: AuditRecord }>("UpdateEvidenceStatus", [
      p.id, p.status, p.performedByDid, p.mspId, p.logId, p.signatureHex
    ], { mspId: p.mspId })
  }

  recordAudit(p: {
    logId: string; targetId: string; caseId: string; action: string; performedByDid: string; mspId: string; details?: string
  }) {
    return this.submit<AuditRecord>("RecordAuditAccess", [
      p.logId, p.targetId, p.caseId, p.action, p.performedByDid, p.mspId, p.details || ""
    ], { mspId: p.mspId })
  }

  async readEvidence(id: string): Promise<EvidenceRecord | null> {
    return this.ledger.evaluate("ReadEvidence", [id])
  }

  async readAudit(logId: string): Promise<AuditRecord | null> {
    return this.ledger.evaluate("ReadAudit", [logId])
  }

  async listAudit(): Promise<AuditRecord[]> {
    return (await this.ledger.evaluate<AuditRecord[]>("ListAudit", [])) || []
  }

  async listEvidence(): Promise<EvidenceRecord[]> {
    return (await this.ledger.evaluate<EvidenceRecord[]>("ListEvidence", [])) || []
  }

  info(): Promise<LedgerInfo> {
    return this.ledger.info()
  }

  async verifyChain(): Promise<ChainVerification | null> {
    return this.ledger.verifyChain ? this.ledger.verifyChain() : null
  }

  async close(): Promise<void> {
    await this.ledger.close?.()
  }
}

export const hyperledgerService = new HyperledgerFabricService()
