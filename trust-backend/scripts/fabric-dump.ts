import dotenv from "dotenv"
dotenv.config({ quiet: true })
import path from "path"
import { hyperledgerService } from "../src/services/hyperledger.service"

process.env.LEDGER_MODE = "fabric"
if (!process.env.FABRIC_ORGS_FILE) {
  process.env.FABRIC_ORGS_FILE = path.resolve(__dirname, "../../fabric/multi-org/.run/gateway-orgs.json")
}

async function main() {
  console.log("================================================================================")
  console.log("                HYPERLEDGER FABRIC ON-CHAIN STATE DUMP                          ")
  console.log("================================================================================")
  const info = await hyperledgerService.info()
  console.log("Ledger Mode: " + info.mode)
  console.log("Channel:     " + info.channel)
  console.log("Chaincode:   " + info.chaincode)
  console.log("Connected Peers:\n  " + (info.endpoint || "").split(", ").join("\n  "))
  console.log("================================================================================\n")

  console.log("--------------------------------------------------------------------------------")
  console.log(" 1. EVIDENCE ASSETS COMMITTED TO FABRIC WORLD STATE (EVIDENCE_* keys)")
  console.log("--------------------------------------------------------------------------------")
  const evidence = await hyperledgerService.listEvidence()
  console.log(`Found ${evidence.length} evidence asset(s) on-chain:\n`)
  evidence.forEach((ev, i) => {
    console.log(`[${i + 1}] ID: ${ev.id}`)
    console.log(`    Case ID:      ${ev.caseId}`)
    console.log(`    Status:       ${ev.status.toUpperCase()}`)
    console.log(`    File SHA-256: ${ev.fileHash}`)
    console.log(`    Uploader:     ${ev.uploadedByDid} [${ev.orgMspId}]`)
    console.log(`    Created Tx:   ${ev.createdTxId}`)
    console.log(`    Last Tx:      ${ev.lastTxId}`)
    console.log(`    Timestamp:    ${ev.createdAt}`)
    if (ev.privateDetailsHash) {
      console.log(`    PDC Hash:     ${ev.privateDetailsHash} (in private collection)`)
    }
    console.log("")
  })

  console.log("--------------------------------------------------------------------------------")
  console.log(" 2. IMMUTABLE AUDIT TRAIL COMMITTED TO FABRIC WORLD STATE (AUDIT_* keys)")
  console.log("--------------------------------------------------------------------------------")
  const audit = await hyperledgerService.listAudit()
  console.log(`Found ${audit.length} audit trail event(s) on-chain:\n`)
  
  // Sort by timestamp descending
  audit.sort((a, b) => new Date(b.timestamp).getTime() - new Date(a.timestamp).getTime())

  audit.forEach((a, i) => {
    console.log(`[${i + 1}] Log ID: ${a.logId} | Action: ${a.action.toUpperCase()}`)
    console.log(`    Target:       ${a.targetId} (Case: ${a.caseId})`)
    console.log(`    Performer:    ${a.performedByDid} [${a.orgMspId}]`)
    console.log(`    Submitter:    ${a.submitterMspId}`)
    console.log(`    Fabric Tx ID: ${a.txId}`)
    console.log(`    Timestamp:    ${a.timestamp}`)
    if (a.details) {
      const d = a.details.length > 90 ? a.details.slice(0, 90) + "..." : a.details
      console.log(`    Details:      ${d}`)
    }
    console.log("")
  })

  console.log("================================================================================")
  console.log(`Total On-Chain Records: ${evidence.length} Evidence Assets + ${audit.length} Audit Events`)
  console.log("================================================================================")
  process.exit(0)
}

main().catch(err => {
  console.error("Fabric query failed:", err)
  process.exit(1)
})

