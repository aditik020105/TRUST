/**
 * Checks that the embedded policy evaluator (used when OPA_URL is unset) makes exactly the same
 * allow/deny decisions as a real OPA server running policies/trust_authz.rego.
 *
 *   opa run --server --addr 127.0.0.1:8181 policies/trust_authz.rego
 *   OPA_URL=http://127.0.0.1:8181 npm run opa:parity
 */
import { opaService } from "../src/services/opa.service"

const OPA_URL = (process.env.OPA_URL || "http://127.0.0.1:8181").replace(/\/$/, "")
const roles = ["admin", "investigator", "analyst", "judiciary", "auditor"]
const statuses = ["approved", "pending", "revoked"]
const actions = [
  "list_evidence", "inspect_evidence", "view_evidence", "download_evidence", "verify_integrity", "read_audit_log",
  "upload_evidence", "update_evidence_status", "approve_user", "revoke_user", "manage_users", "manage_firewall",
  "view_policy", "audit_ledger", "read_private_details", "delegate_case_access", "export_report", "import_legacy", "unknown_action"
]

async function main() {
  let n = 0
  const mismatches: string[] = []
  for (const role of roles) for (const status of statuses) for (const action of actions) {
    const paramSets = action === "update_evidence_status" ? [{ status: "verified" }, { status: "flagged" }, { status: "pending" }] : [{}]
    for (const parameters of paramSets) for (const did of [`did:trust:${role}:abc`, "not-a-did"]) {
      const input: any = { method: "T", path: "/", resource: "/", action, parameters, user: { did, role, mspId: "M", status } }
      const embedded = opaService.evaluateEmbeddedRego(input).allow
      const res = await fetch(`${OPA_URL}/v1/data/trust/authz/allow`, { method: "POST", body: JSON.stringify({ input }) })
      const remote = ((await res.json()) as any).result === true
      n++
      if (embedded !== remote) mismatches.push(`${role}/${status}/${action}/${JSON.stringify(parameters)}/${did}: embedded=${embedded} opa=${remote}`)
    }
  }
  console.log(`${n} role/status/action combinations checked against ${OPA_URL}: ${mismatches.length} mismatches`)
  mismatches.forEach(m => console.log("  " + m))
  process.exit(mismatches.length ? 1 : 0)
}

main().catch(err => {
  console.error(`Could not reach OPA at ${OPA_URL}: ${err.message}`)
  process.exit(1)
})
