/**
 * Restores a backup into the configured (empty) database and storage, verifies every file
 * against the manifest, then reconciles the restored database with the ledger and prints
 * every disagreement (e.g. a revocation or status change made after the backup was taken).
 *
 *   npm run restore -- backups/<dir> [--force]
 */
import dotenv from "dotenv"
dotenv.config({ quiet: true })
import path from "path"
import { restoreBackup } from "../src/services/backup.service"

const dir = process.argv[2]
if (!dir) {
  console.error("usage: npm run restore -- <backup dir> [--force]")
  process.exit(1)
}
restoreBackup(path.resolve(dir), { force: process.argv.includes("--force") })
  .then(r => {
    for (const [t, n] of Object.entries(r.restored)) console.log(`  restored ${t}: ${n}`)
    console.log(`  restored blobs: ${r.blobs}`)
    const rec = r.reconciliation
    console.log(rec.ok ? "Reconciliation: database agrees with the ledger." : `Reconciliation: ${rec.issues.length} issue(s) — review before use:`)
    for (const i of rec.issues) console.log(`  - ${i.kind} ${i.id}: ${i.detail}`)
    process.exit(rec.ok ? 0 : 2)
  })
  .catch(err => {
    console.error(err.message || err)
    process.exit(1)
  })
