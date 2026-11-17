import crypto from "crypto"
import fs from "fs"
import path from "path"
import { SUBMIT_FUNCTIONS, EVALUATE_FUNCTIONS, LedgerStub } from "./evidence-logic"
import { Ledger, LedgerTxResult, SubmitFn, EvaluateFn, LedgerInfo, ChainVerification, LedgerCallOptions } from "./types"

/**
 * Append-only, hash-chained ledger stored in a single JSON file.
 *
 * Each committed transaction becomes one block:
 *   hash = SHA-256(number | prevHash | timestamp | txId | fn | args | writes)
 * World state is never read from disk directly; it is rebuilt by replaying the
 * blocks on startup, so editing a record in the file breaks the chain and is
 * reported by verifyChain(). This is a stand-in for a Fabric network during
 * development and tests, not a replacement for one: a single process controls
 * the file, so it gives tamper evidence, not distributed trust.
 */

interface BlockWrite { key: string; value: string }
interface Block {
  number: number
  prevHash: string
  hash: string
  timestamp: string
  txId: string
  fn: string
  args: string[]
  mspId: string
  writes: BlockWrite[]
}

const GENESIS_PREV = "0".repeat(64)

function blockHash(b: Omit<Block, "hash">): string {
  return crypto
    .createHash("sha256")
    .update(
      [b.number, b.prevHash, b.timestamp, b.txId, b.fn, JSON.stringify(b.args), b.mspId, JSON.stringify(b.writes)].join("|")
    )
    .digest("hex")
}

export class LocalLedger implements Ledger {
  private blocks: Block[] = []
  private state = new Map<string, string>()
  /** Private data lives outside the blocks (like a Fabric peer's private store); blocks hold only its hash. */
  private privateStore = new Map<string, string>()
  /** Organisations allowed to read the private collection, emulating the Fabric collection policy. */
  private privateMembers = (process.env.PRIVATE_DATA_MEMBERS || "PoliceOrgMSP,JudiciaryOrgMSP,AdminOrgMSP").split(",").map(s => s.trim())
  private loaded = false
  private queue: Promise<unknown> = Promise.resolve()

  constructor(
    private filePath: string,
    private mspId: string = process.env.FABRIC_MSP_ID || "TrustGatewayMSP",
    private channel: string = process.env.FABRIC_CHANNEL || "evidence-channel",
    private chaincode: string = process.env.FABRIC_CHAINCODE || "evidence-contract"
  ) {}

  private load(): void {
    if (this.loaded) return
    this.loaded = true
    if (!fs.existsSync(this.filePath)) return
    const parsed = JSON.parse(fs.readFileSync(this.filePath, "utf-8"))
    this.blocks = Array.isArray(parsed.blocks) ? parsed.blocks : []
    for (const b of this.blocks) for (const w of b.writes) this.state.set(w.key, w.value)
    if (fs.existsSync(this.privatePath())) {
      const priv = JSON.parse(fs.readFileSync(this.privatePath(), "utf-8"))
      for (const [k, v] of Object.entries(priv)) this.privateStore.set(k, String(v))
    }
  }

  private privatePath(): string {
    return this.filePath.replace(/\.json$/, "") + ".private.json"
  }

  private persist(): void {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true })
    const tmp = `${this.filePath}.tmp`
    fs.writeFileSync(tmp, JSON.stringify({ format: "trust-local-ledger/1", blocks: this.blocks }, null, 1))
    fs.renameSync(tmp, this.filePath)
  }

  private makeStub(
    txId: string,
    timestamp: string,
    writes: BlockWrite[] | null,
    opts: LedgerCallOptions = {},
    privateWrites?: Map<string, string>
  ): LedgerStub {
    const pending = new Map<string, string>()
    const sha = (d: Uint8Array) => crypto.createHash("sha256").update(d).digest("hex")
    return {
      getTransient: key => opts.transient?.[key],
      sha256Hex: sha,
      putPrivateData: async (collection, key, value) => {
        if (!writes || !privateWrites) throw new Error("putPrivateData is not allowed in a query")
        const k = `${collection}|${key}`
        privateWrites.set(k, Buffer.from(value).toString("utf-8"))
        // the block records only the hash, as on Fabric
        writes.push({ key: `PRIVHASH|${k}`, value: sha(value) })
      },
      getPrivateData: async (collection, key) => {
        if (opts.mspId && !this.privateMembers.includes(opts.mspId)) return undefined
        const v = this.privateStore.get(`${collection}|${key}`)
        return v === undefined ? undefined : Buffer.from(v, "utf-8")
      },
      getState: async key => {
        const v = pending.get(key) ?? this.state.get(key)
        return v === undefined ? undefined : Buffer.from(v, "utf-8")
      },
      putState: async (key, value) => {
        if (!writes) throw new Error("putState is not allowed in a query")
        const s = Buffer.from(value).toString("utf-8")
        pending.set(key, s)
        writes.push({ key, value: s })
      },
      getStateByRange: async (start, end) => {
        const out: Array<{ key: string; value: Uint8Array }> = []
        for (const [k, v] of this.state) if (k >= start && k < end) out.push({ key: k, value: Buffer.from(v, "utf-8") })
        return out.sort((a, b) => (a.key < b.key ? -1 : 1))
      },
      getTxID: () => txId,
      getTxTimestamp: () => timestamp,
      getCreatorMspId: () => this.mspId
    }
  }

  async submit<T = any>(fn: SubmitFn, args: string[], opts: LedgerCallOptions = {}): Promise<LedgerTxResult<T>> {
    // Serialize commits so block numbers and prevHash links stay consistent.
    const run = async (): Promise<LedgerTxResult<T>> => {
      this.load()
      const impl = SUBMIT_FUNCTIONS[fn] as (stub: LedgerStub, ...a: string[]) => Promise<T>
      if (!impl) throw new Error(`Unknown ledger function ${fn}`)
      const timestamp = new Date().toISOString()
      const txId = crypto.createHash("sha256").update(`${fn}|${JSON.stringify(args)}|${timestamp}|${crypto.randomBytes(16).toString("hex")}`).digest("hex")
      const writes: BlockWrite[] = []
      const privateWrites = new Map<string, string>()
      const result = await impl(this.makeStub(txId, timestamp, writes, opts, privateWrites), ...args)

      const prev = this.blocks[this.blocks.length - 1]
      const unsigned = {
        number: this.blocks.length,
        prevHash: prev ? prev.hash : GENESIS_PREV,
        timestamp,
        txId,
        fn,
        args,
        mspId: this.mspId,
        writes
      }
      const block: Block = { ...unsigned, hash: blockHash(unsigned) }
      this.blocks.push(block)
      try {
        this.persist()
      } catch (err) {
        this.blocks.pop()
        throw err
      }
      for (const w of writes) this.state.set(w.key, w.value)
      if (privateWrites.size) {
        for (const [k, v] of privateWrites) this.privateStore.set(k, v)
        fs.writeFileSync(this.privatePath(), JSON.stringify(Object.fromEntries(this.privateStore), null, 1), { mode: 0o600 })
      }
      return { txId, blockNumber: block.number, result }
    }
    const p = this.queue.then(run, run)
    this.queue = p.catch(() => undefined)
    return p
  }

  async evaluate<T = any>(fn: EvaluateFn, args: string[], opts: LedgerCallOptions = {}): Promise<T> {
    this.load()
    const impl = EVALUATE_FUNCTIONS[fn] as (stub: LedgerStub, ...a: string[]) => Promise<T>
    if (!impl) throw new Error(`Unknown ledger query ${fn}`)
    return impl(this.makeStub("query", new Date().toISOString(), null, opts), ...args)
  }

  async info(): Promise<LedgerInfo> {
    this.load()
    return { mode: "local", channel: this.channel, chaincode: this.chaincode, mspId: this.mspId, height: this.blocks.length, endpoint: this.filePath }
  }

  /** Re-reads the file from disk and recomputes every block hash and link. */
  async verifyChain(): Promise<ChainVerification> {
    let blocks: Block[] = []
    try {
      blocks = fs.existsSync(this.filePath) ? JSON.parse(fs.readFileSync(this.filePath, "utf-8")).blocks || [] : []
    } catch (err: any) {
      return { ok: false, height: 0, checkedBlocks: 0, reason: `ledger file unreadable: ${err.message}` }
    }
    let prevHash = GENESIS_PREV
    for (let i = 0; i < blocks.length; i++) {
      const { hash, ...rest } = blocks[i]
      if (rest.number !== i) return { ok: false, height: blocks.length, checkedBlocks: i, firstBadBlock: i, reason: "block number out of sequence" }
      if (rest.prevHash !== prevHash) return { ok: false, height: blocks.length, checkedBlocks: i, firstBadBlock: i, reason: "prevHash does not link to previous block" }
      if (blockHash(rest) !== hash) return { ok: false, height: blocks.length, checkedBlocks: i, firstBadBlock: i, reason: "block contents do not match its hash" }
      prevHash = hash
    }
    // The in-memory state must match the replay of the file (detects edits made while running).
    if (this.loaded) {
      if (blocks.length !== this.blocks.length) {
        return { ok: false, height: blocks.length, checkedBlocks: blocks.length, reason: `file has ${blocks.length} blocks but ${this.blocks.length} were committed` }
      }
      const diverged = blocks.findIndex((b, i) => b.hash !== this.blocks[i].hash)
      if (diverged >= 0) {
        return { ok: false, height: blocks.length, checkedBlocks: diverged, firstBadBlock: diverged, reason: "file was rewritten with a different (re-hashed) history" }
      }
    }
    return { ok: true, height: blocks.length, checkedBlocks: blocks.length }
  }
}
