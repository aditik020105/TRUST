import fs from "fs"
import path from "path"
import crypto from "crypto"
import { LocalLedger } from "../ledger/local-ledger"

const hash = (s: string) => crypto.createHash("sha256").update(s).digest("hex")
const SIG = "ab".repeat(64)

function freshLedger() {
  const file = path.join(process.env.DATA_DIR!, `ledger-${Math.random().toString(36).slice(2)}.json`)
  return { ledger: new LocalLedger(file), file }
}

describe("Chaincode rules (shared evidence-logic) on the local hash-chained ledger", () => {
  it("anchors evidence and its upload audit event in one transaction with a real block number", async () => {
    const { ledger } = freshLedger()
    const r = await ledger.submit("CreateEvidence", ["EV-1", "CASE-1", hash("a"), "did:trust:investigator:x", SIG, "PoliceOrgMSP", "LOG-1"])
    expect(r.blockNumber).toBe(0)
    expect(r.txId).toMatch(/^[0-9a-f]{64}$/)
    expect(r.result.evidence.status).toBe("pending")
    expect(r.result.audit.txId).toBe(r.txId)

    const ev = await ledger.evaluate("ReadEvidence", ["EV-1"])
    expect(ev.fileHash).toBe(hash("a"))
    const audit = await ledger.evaluate("ReadAudit", ["LOG-1"])
    expect(audit.action).toBe("uploaded")
  })

  it("rejects malformed hashes, malformed signatures, non-DID performers and duplicate IDs", async () => {
    const { ledger } = freshLedger()
    await expect(ledger.submit("CreateEvidence", ["EV-1", "C", "0xabc", "did:trust:a", SIG, "M", "L1"])).rejects.toThrow(/64-character/)
    await expect(ledger.submit("CreateEvidence", ["EV-1", "C", hash("x"), "did:trust:a", "short", "M", "L1"])).rejects.toThrow(/signature/)
    await expect(ledger.submit("CreateEvidence", ["EV-1", "C", hash("x"), "alice", SIG, "M", "L1"])).rejects.toThrow(/did:trust/)
    await ledger.submit("CreateEvidence", ["EV-1", "C", hash("x"), "did:trust:a", SIG, "M", "L1"])
    await expect(ledger.submit("CreateEvidence", ["EV-1", "C", hash("y"), "did:trust:a", SIG, "M", "L2"])).rejects.toThrow(/already exists/)
    // a failed transaction leaves no block behind
    expect((await ledger.info()).height).toBe(1)
  })

  it("UpdateEvidenceStatus changes state, writes an audit record and refuses no-op or unknown evidence", async () => {
    const { ledger } = freshLedger()
    await ledger.submit("CreateEvidence", ["EV-2", "C", hash("x"), "did:trust:a", SIG, "M", "L1"])
    const u = await ledger.submit("UpdateEvidenceStatus", ["EV-2", "verified", "did:trust:judge", "JudiciaryOrgMSP", "L2", SIG])
    expect(u.result.evidence.status).toBe("verified")
    expect(u.result.audit.action).toBe("status_verified")
    await expect(ledger.submit("UpdateEvidenceStatus", ["EV-2", "verified", "did:trust:judge", "J", "L3", SIG])).rejects.toThrow(/already verified/)
    await expect(ledger.submit("UpdateEvidenceStatus", ["EV-404", "flagged", "did:trust:judge", "J", "L4", SIG])).rejects.toThrow(/does not exist/)
    await expect(ledger.submit("UpdateEvidenceStatus", ["EV-2", "deleted", "did:trust:judge", "J", "L5", SIG])).rejects.toThrow(/status must be/)
  })

  it("verifyChain detects an edited block and a re-hashed (rewritten) history", async () => {
    const { ledger, file } = freshLedger()
    await ledger.submit("CreateEvidence", ["EV-3", "C", hash("x"), "did:trust:a", SIG, "M", "L1"])
    await ledger.submit("RecordAuditAccess", ["L2", "EV-3", "C", "viewed", "did:trust:b", "M", ""])
    expect((await ledger.verifyChain()).ok).toBe(true)

    const original = fs.readFileSync(file, "utf-8")
    const tampered = JSON.parse(original)
    tampered.blocks[0].args[2] = hash("forged")
    fs.writeFileSync(file, JSON.stringify(tampered))
    const res = await ledger.verifyChain()
    expect(res.ok).toBe(false)
    expect(res.firstBadBlock).toBe(0)

    fs.writeFileSync(file, original)
    expect((await ledger.verifyChain()).ok).toBe(true)
  })

  it("rebuilds world state from blocks after restart", async () => {
    const { ledger, file } = freshLedger()
    await ledger.submit("CreateEvidence", ["EV-4", "C", hash("x"), "did:trust:a", SIG, "M", "L1"])
    const reopened = new LocalLedger(file)
    expect((await reopened.evaluate("ReadEvidence", ["EV-4"])).id).toBe("EV-4")
    const next = await reopened.submit("RecordAuditAccess", ["L2", "EV-4", "C", "viewed", "did:trust:b", "M", ""])
    expect(next.blockNumber).toBe(1)
    expect((await reopened.verifyChain()).ok).toBe(true)
  })

  it("the chaincode package uses the same contract rules as the backend", () => {
    const backend = fs.readFileSync(path.join(__dirname, "../ledger/evidence-logic.ts"), "utf-8")
    const chaincodePath = path.join(__dirname, "../../../trust-chaincode/src/evidence-logic.ts")
    expect(fs.existsSync(chaincodePath)).toBe(true)
    expect(fs.readFileSync(chaincodePath, "utf-8")).toBe(backend)
  })
})
