import fs from "fs"
import path from "path"
import crypto from "crypto"
import { Ledger, LedgerTxResult, SubmitFn, EvaluateFn, LedgerInfo, LedgerCallOptions } from "./types"

/**
 * Hyperledger Fabric Gateway client (Fabric v2.4+).
 *
 * Multi-organisation (recommended): FABRIC_ORGS_FILE points to a JSON file written by
 * fabric/multi-org/start-network.sh:
 *   {
 *     "channel": "evidence-channel", "chaincode": "evidence-contract", "defaultOrg": "PoliceOrgMSP",
 *     "appMspMap": { "AdminOrgMSP": "JudiciaryOrgMSP" },
 *     "orgs": { "PoliceOrgMSP": { "peerEndpoint": "127.0.0.1:7051", "hostAlias": "peer0.police.trust.local",
 *                "tlsCertPath": "...", "certPath": "...", "keyPath": "..." }, ... },
 *     "privateCollectionMembers": ["PoliceOrgMSP", "JudiciaryOrgMSP"]
 *   }
 * Each action is endorsed and submitted with the identity of the acting user's organisation,
 * so the ledger records which agency submitted it, and the chaincode endorsement policy
 * (e.g. 2 of 3 organisations) is enforced by the peers.
 *
 * Single organisation: FABRIC_PEER_ENDPOINT, FABRIC_PEER_HOST_ALIAS, FABRIC_TLS_CERT_PATH,
 * FABRIC_CERT_PATH, FABRIC_KEY_PATH, FABRIC_MSP_ID, FABRIC_CHANNEL, FABRIC_CHAINCODE.
 */

interface OrgConfig {
  mspId: string
  peerEndpoint: string
  hostAlias?: string
  tlsCertPath: string
  certPath: string
  keyPath: string
}

interface NetworkConfig {
  channel: string
  chaincode: string
  defaultOrg: string
  appMspMap: Record<string, string>
  orgs: Record<string, OrgConfig>
  privateCollectionMembers: string[]
}

function normalizePath(p: string): string {
  if (process.platform === "win32" && p.startsWith("/mnt/")) {
    const drive = p.charAt(5).toUpperCase()
    return `${drive}:${p.slice(6)}`
  }
  return p
}

function readPem(p: string): Buffer {
  p = normalizePath(p)
  const stat = fs.statSync(p)
  if (stat.isDirectory()) {
    const file = fs.readdirSync(p).find(f => !f.startsWith("."))
    if (!file) throw new Error(`No credential file found in ${p}`)
    return fs.readFileSync(path.join(p, file))
  }
  return fs.readFileSync(p)
}

function required(name: string): string {
  const v = process.env[name]
  if (!v) throw new Error(`LEDGER_MODE=fabric requires ${name} (or FABRIC_ORGS_FILE)`)
  return v
}

function loadConfig(): NetworkConfig {
  if (process.env.FABRIC_ORGS_FILE) {
    const orgsFilePath = normalizePath(process.env.FABRIC_ORGS_FILE)
    const raw = JSON.parse(fs.readFileSync(orgsFilePath, "utf-8"))
    for (const [msp, o] of Object.entries<any>(raw.orgs)) {
      o.mspId = o.mspId || msp
      if (o.tlsCertPath) o.tlsCertPath = normalizePath(o.tlsCertPath)
      if (o.certPath) o.certPath = normalizePath(o.certPath)
      if (o.keyPath) o.keyPath = normalizePath(o.keyPath)
    }
    return {
      channel: raw.channel || "evidence-channel",
      chaincode: raw.chaincode || "evidence-contract",
      defaultOrg: raw.defaultOrg || Object.keys(raw.orgs)[0],
      appMspMap: raw.appMspMap || {},
      orgs: raw.orgs,
      privateCollectionMembers: raw.privateCollectionMembers || []
    }
  }
  const mspId = required("FABRIC_MSP_ID")
  return {
    channel: process.env.FABRIC_CHANNEL || "evidence-channel",
    chaincode: process.env.FABRIC_CHAINCODE || "evidence-contract",
    defaultOrg: mspId,
    appMspMap: {},
    orgs: {
      [mspId]: {
        mspId,
        peerEndpoint: required("FABRIC_PEER_ENDPOINT"),
        hostAlias: process.env.FABRIC_PEER_HOST_ALIAS,
        tlsCertPath: required("FABRIC_TLS_CERT_PATH"),
        certPath: required("FABRIC_CERT_PATH"),
        keyPath: required("FABRIC_KEY_PATH")
      }
    },
    privateCollectionMembers: (process.env.PRIVATE_DATA_MEMBERS || "").split(",").map(s => s.trim()).filter(Boolean)
  }
}

interface Connection { client: any; gateway: any; contract: any }

export class FabricLedger implements Ledger {
  private cfg = loadConfig()
  private connections = new Map<string, Promise<Connection>>()

  /** Maps an application MSP (PoliceOrgMSP, AdminOrgMSP, ...) to a configured Fabric organisation. */
  private orgFor(appMsp?: string): OrgConfig {
    const mapped = appMsp ? this.cfg.appMspMap[appMsp] || appMsp : undefined
    return (mapped && this.cfg.orgs[mapped]) || this.cfg.orgs[this.cfg.defaultOrg]
  }

  private connect(org: OrgConfig): Promise<Connection> {
    let c = this.connections.get(org.mspId)
    if (!c) {
      c = (async () => {
        const grpc = require("@grpc/grpc-js")
        const { connect, signers, hash } = require("@hyperledger/fabric-gateway")
        const client = new grpc.Client(org.peerEndpoint, grpc.credentials.createSsl(readPem(org.tlsCertPath)), {
          "grpc.ssl_target_name_override": org.hostAlias || org.peerEndpoint.split(":")[0]
        })
        const gateway = connect({
          client,
          identity: { mspId: org.mspId, credentials: readPem(org.certPath) },
          signer: signers.newPrivateKeySigner(crypto.createPrivateKey(readPem(org.keyPath))),
          hash: hash.sha256,
          evaluateOptions: () => ({ deadline: Date.now() + 5000 }),
          endorseOptions: () => ({ deadline: Date.now() + 15000 }),
          submitOptions: () => ({ deadline: Date.now() + 5000 }),
          commitStatusOptions: () => ({ deadline: Date.now() + 60000 })
        })
        const contract = gateway.getNetwork(this.cfg.channel).getContract(this.cfg.chaincode)
        return { client, gateway, contract }
      })()
      c.catch(() => this.connections.delete(org.mspId))
      this.connections.set(org.mspId, c)
    }
    return c
  }

  async submit<T = any>(fn: SubmitFn, args: string[], opts: LedgerCallOptions = {}): Promise<LedgerTxResult<T>> {
    const org = this.orgFor(opts.mspId)
    const { contract } = await this.connect(org)
    const proposalOpts: any = { arguments: args }
    if (opts.transient && Object.keys(opts.transient).length) {
      proposalOpts.transientData = opts.transient
      // Private data may only be endorsed by peers of collection member organisations.
      if (this.cfg.privateCollectionMembers.length) proposalOpts.endorsingOrganizations = this.cfg.privateCollectionMembers
    }
    const transaction = await contract.newProposal(fn, proposalOpts).endorse()
    const submitted = await transaction.submit()
    const status = await submitted.getStatus()
    if (!status.successful) {
      throw new Error(`Fabric transaction ${status.transactionId} failed to commit with status code ${status.code}`)
    }
    const raw = Buffer.from(transaction.getResult()).toString("utf-8")
    return { txId: status.transactionId, blockNumber: Number(status.blockNumber), result: raw ? JSON.parse(raw) : (undefined as T) }
  }

  async evaluate<T = any>(fn: EvaluateFn, args: string[], opts: LedgerCallOptions = {}): Promise<T> {
    // Queries run on the acting organisation's own peer, so private data is only readable by members.
    const { contract } = await this.connect(this.orgFor(opts.mspId))
    const bytes = await contract.evaluate(fn, { arguments: args })
    const raw = Buffer.from(bytes).toString("utf-8")
    return raw ? JSON.parse(raw) : (null as T)
  }

  async info(): Promise<LedgerInfo> {
    const orgs = Object.keys(this.cfg.orgs)
    return {
      mode: "fabric",
      channel: this.cfg.channel,
      chaincode: this.cfg.chaincode,
      mspId: orgs.join(", "),
      endpoint: orgs.map(o => `${o}@${this.cfg.orgs[o].peerEndpoint}`).join(", ")
    }
  }

  async close(): Promise<void> {
    for (const c of this.connections.values()) {
      try {
        const { gateway, client } = await c
        gateway.close()
        client.close()
      } catch { /* ignore */ }
    }
    this.connections.clear()
  }
}
