/**
 * Off-chain backup: every table, every encrypted evidence blob, SHA-256 manifest.
 * Blobs stay encrypted; keep EVIDENCE_ENCRYPTION_KEY somewhere else. The ledger is not backed up
 * here: its peers keep it, and a restored database is checked against it.
 *
 *   npm run backup                      -> backups/<timestamp>/
 *   npm run restore -- backups/<dir>     (see scripts/restore.ts)
 */
import dotenv from "dotenv"
dotenv.config({ quiet: true })
import path from "path"
import { createBackup } from "../src/services/backup.service"

const dir = path.join(__dirname, "..", "backups", new Date().toISOString().replace(/[:.]/g, "-"))
createBackup(dir)
  .then(r => {
    for (const [t, n] of Object.entries(r.counts)) console.log(`  ${t}: ${n} rows`)
    console.log(`  blobs: ${r.blobs}\nBackup written to ${r.dir}`)
    process.exit(0)
  })
  .catch(err => {
    console.error(err)
    process.exit(1)
  })
