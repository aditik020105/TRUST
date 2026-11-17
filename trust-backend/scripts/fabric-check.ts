/**
 * Proves, against a running multi-org network (fabric/multi-org/start-network.sh), that:
 *   1. each transaction is submitted as the acting agency and endorsed by 2 of the 3 agencies' peers
 *   2. private case notes are readable on member peers (Police, Judiciary) and NOT on Forensics
 *   3. the chaincode rejects invalid writes on every peer
 *
 *   FABRIC_ORGS_FILE=../fabric/multi-org/.run/gateway-orgs.json npm run fabric:check
 */
import dotenv from "dotenv"
dotenv.config({ quiet: true })
import fs from "fs"
import path from "path"
import crypto from "crypto"
import { FabricLedger } from "../src/ledger/fabric-ledger"

process.env.LEDGER_MODE = "fabric"
if (!process.env.FABRIC_ORGS_FILE) {
  process.env.FABRIC_ORGS_FILE = path.resolve(__dirname, "../../fabric/multi-org/.run/gateway-orgs.json")
}

function normalizePath(p: string): string {
  if (process.platform === "win32" && p.startsWith("/mnt/")) {
    const drive = p.charAt(5).toUpperCase()
    return `${drive}:${p.slice(6)}`
  }
  return p
}

async function endorsersOf(cfgFile: string, txId: string, blockNumber: number): Promise<string[]> {
  const grpc = require("@grpc/grpc-js")
  const { connect, signers, hash } = require("@hyperledger/fabric-gateway")
  const { common, peer, msp } = require("@hyperledger/fabric-protos")
  cfgFile = normalizePath(cfgFile)
  const cfg = JSON.parse(fs.readFileSync(cfgFile, "utf-8"))
  const o = cfg.orgs.JudiciaryOrgMSP
  const pem = (p: string) => {
    p = normalizePath(p)
    return (fs.statSync(p).isDirectory() ? fs.readFileSync(`${p}/${fs.readdirSync(p)[0]}`) : fs.readFileSync(p))
  }
  const client = new grpc.Client(o.peerEndpoint, grpc.credentials.createSsl(pem(o.tlsCertPath)), { "grpc.ssl_target_name_override": o.hostAlias })
  const gw = connect({ client, identity: { mspId: "JudiciaryOrgMSP", credentials: pem(o.certPath) }, signer: signers.newPrivateKeySigner(crypto.createPrivateKey(pem(o.keyPath))), hash: hash.sha256 })
  try {
    const events = await gw.getNetwork(cfg.channel).getBlockEvents({ startBlock: BigInt(blockNumber) })
    for await (const block of events) {
      for (const envBytes of block.getData().getDataList_asU8()) {
        const env = common.Envelope.deserializeBinary(envBytes)
        const payload = common.Payload.deserializeBinary(env.getPayload_asU8())
        const ch = common.ChannelHeader.deserializeBinary(payload.getHeader()!.getChannelHeader_asU8())
        if (ch.getTxId() !== txId) continue
        const tx = peer.Transaction.deserializeBinary(payload.getData_asU8())
        const action = peer.ChaincodeActionPayload.deserializeBinary(tx.getActionsList()[0].getPayload_asU8())
        events.close()
        return action.getAction()!.getEndorsementsList().map((e: any) => msp.SerializedIdentity.deserializeBinary(e.getEndorser_asU8()).getMspid())
      }
    }
    return []
  } finally {
    gw.close()
    client.close()
  }
}

async function main() {
  const ledger = new FabricLedger()
  const id = `EV-CHK${Date.now().toString(36).toUpperCase()}`
  const fileHash = crypto.createHash("sha256").update(id).digest("hex")
  const ok = (b: boolean) => (b ? "PASS" : "FAIL")
  let failures = 0
  const check = (cond: boolean, label: string) => { if (!cond) failures++; console.log(`  [${ok(cond)}] ${label}`) }

  console.log("1. Upload submitted by a forensic analyst (ForensicsOrgMSP) with private notes")
  const tx = await ledger.submit<any>("CreateEvidence", [id, "CASE-CHECK", fileHash, "did:trust:analyst:check", "ab".repeat(64), "ForensicsOrgMSP", `LOG-${id}`], {
    mspId: "ForensicsOrgMSP",
    transient: { private: Buffer.from(JSON.stringify({ fileName: "statement.pdf", notes: "Witness: test" })) }
  })
  console.log(`     tx ${tx.txId} in block ${tx.blockNumber}`)
  check(tx.result.audit.submitterMspId === "ForensicsOrgMSP", `ledger records submitting organisation = ${tx.result.audit.submitterMspId}`)
  const endorsers = await endorsersOf(process.env.FABRIC_ORGS_FILE!, tx.txId, tx.blockNumber)
  check(new Set(endorsers).size >= 2, `endorsed by ${endorsers.join(" + ")} (policy: 2 of Police/Forensics/Judiciary)`)
  check(!endorsers.includes("ForensicsOrgMSP"), "private-data write endorsed only by collection members")

  console.log("2. Status change by a judge (JudiciaryOrgMSP)")
  const st = await ledger.submit<any>("UpdateEvidenceStatus", [id, "verified", "did:trust:judiciary:check", "JudiciaryOrgMSP", `LOG-${id}-V`, "cd".repeat(64)], { mspId: "JudiciaryOrgMSP" })
  const stEndorsers = await endorsersOf(process.env.FABRIC_ORGS_FILE!, st.txId, st.blockNumber)
  check(new Set(stEndorsers).size >= 2, `endorsed by ${stEndorsers.join(" + ")}`)

  console.log("3. Private data collection membership")
  const police = await ledger.evaluate<any>("ReadEvidencePrivate", [id], { mspId: "PoliceOrgMSP" })
  check(police?.notes === "Witness: test" && police.hashMatches, "Police peer returns the notes and they match the on-chain hash")
  const judiciary = await ledger.evaluate<any>("ReadEvidencePrivate", [id], { mspId: "JudiciaryOrgMSP" })
  check(judiciary?.notes === "Witness: test", "Judiciary peer returns the notes")
  let forensicsBlocked = false
  try {
    const f = await ledger.evaluate<any>("ReadEvidencePrivate", [id], { mspId: "ForensicsOrgMSP" })
    forensicsBlocked = !f
  } catch {
    forensicsBlocked = true
  }
  check(forensicsBlocked, "Forensics peer cannot read the notes (it stores only the hash)")
  const pub = await ledger.evaluate<any>("ReadEvidence", [id], { mspId: "ForensicsOrgMSP" })
  check(/^[0-9a-f]{64}$/.test(pub.privateDetailsHash), `public record carries only the hash ${pub.privateDetailsHash.slice(0, 16)}…`)

  console.log("4. Chaincode rules are enforced by the peers")
  let rejected = false
  try {
    await ledger.submit("CreateEvidence", [id, "CASE-CHECK", fileHash, "did:trust:x:y", "ab".repeat(64), "PoliceOrgMSP", `LOG-${id}-DUP`], { mspId: "PoliceOrgMSP" })
  } catch (e: any) {
    rejected = /already exists/.test(e.message + JSON.stringify(e.details || ""))
  }
  check(rejected, "duplicate evidence ID rejected at endorsement")

  await ledger.close()
  console.log(failures ? `\n${failures} check(s) FAILED` : "\nAll checks passed.")
  process.exit(failures ? 1 : 0)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
