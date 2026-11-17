import { Context, Contract, Info, Transaction, Returns } from "fabric-contract-api"
import { createHash } from "crypto"
import * as logic from "./evidence-logic"

/**
 * Adapts a Fabric transaction context to the LedgerStub used by evidence-logic.ts,
 * so the chaincode enforces exactly the same rules as the backend's local ledger.
 */
function stubFor(ctx: Context): logic.LedgerStub {
  return {
    getState: async key => {
      const v = await ctx.stub.getState(key)
      return v && v.length ? v : undefined
    },
    putState: async (key, value) => {
      await ctx.stub.putState(key, Buffer.from(value))
    },
    getStateByRange: async (start, end) => {
      const out: Array<{ key: string; value: Uint8Array }> = []
      const iterator = await ctx.stub.getStateByRange(start, end)
      let res = await iterator.next()
      while (!res.done) {
        if (res.value) out.push({ key: res.value.key, value: res.value.value })
        res = await iterator.next()
      }
      await iterator.close()
      return out
    },
    getTxID: () => ctx.stub.getTxID(),
    getTxTimestamp: () => {
      const ts = ctx.stub.getTxTimestamp()
      const ms = Number(ts.seconds.toString()) * 1000 + Math.floor(ts.nanos / 1e6)
      return new Date(ms).toISOString()
    },
    getCreatorMspId: () => ctx.clientIdentity.getMSPID(),
    getTransient: key => {
      const v = ctx.stub.getTransient().get(key)
      return v && v.length ? v : undefined
    },
    putPrivateData: async (collection, key, value) => {
      await ctx.stub.putPrivateData(collection, key, Buffer.from(value))
    },
    getPrivateData: async (collection, key) => {
      const v = await ctx.stub.getPrivateData(collection, key)
      return v && v.length ? v : undefined
    },
    sha256Hex: data => createHash("sha256").update(data).digest("hex")
  }
}

const json = (o: unknown) => JSON.stringify(o)

@Info({ title: "EvidenceContract", description: "TRUST chain-of-custody evidence and audit records" })
export class EvidenceContract extends Contract {
  constructor() {
    super("evidence-contract")
  }

  @Transaction()
  @Returns("string")
  public async CreateEvidence(
    ctx: Context, id: string, caseId: string, fileHash: string, uploadedByDid: string,
    uploaderSignature: string, orgMspId: string, logId: string
  ): Promise<string> {
    return json(await logic.CreateEvidence(stubFor(ctx), id, caseId, fileHash, uploadedByDid, uploaderSignature, orgMspId, logId))
  }

  @Transaction()
  @Returns("string")
  public async UpdateEvidenceStatus(
    ctx: Context, id: string, newStatus: string, performedByDid: string, orgMspId: string, logId: string, signature: string
  ): Promise<string> {
    return json(await logic.UpdateEvidenceStatus(stubFor(ctx), id, newStatus, performedByDid, orgMspId, logId, signature))
  }

  @Transaction()
  @Returns("string")
  public async RecordAuditAccess(
    ctx: Context, logId: string, targetId: string, caseId: string, action: string,
    performedByDid: string, orgMspId: string, details: string
  ): Promise<string> {
    return json(await logic.RecordAuditAccess(stubFor(ctx), logId, targetId, caseId, action, performedByDid, orgMspId, details))
  }

  @Transaction(false)
  @Returns("string")
  public async ReadEvidence(ctx: Context, id: string): Promise<string> {
    return json(await logic.ReadEvidence(stubFor(ctx), id))
  }

  @Transaction(false)
  @Returns("string")
  public async ReadEvidencePrivate(ctx: Context, id: string): Promise<string> {
    return json(await logic.ReadEvidencePrivate(stubFor(ctx), id))
  }

  @Transaction(false)
  @Returns("string")
  public async ReadAudit(ctx: Context, logId: string): Promise<string> {
    return json(await logic.ReadAudit(stubFor(ctx), logId))
  }

  @Transaction(false)
  @Returns("string")
  public async ListAudit(ctx: Context): Promise<string> {
    return json(await logic.ListAudit(stubFor(ctx)))
  }

  @Transaction(false)
  @Returns("string")
  public async ListEvidence(ctx: Context): Promise<string> {
    return json(await logic.ListEvidence(stubFor(ctx)))
  }
}
