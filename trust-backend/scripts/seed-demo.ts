/**
 * Creates demo accounts for a viva / local demo and writes each account's PRIVATE key to a
 * key file, exactly like the browser does at sign-up. The server only stores public keys.
 *
 *   npm run seed:demo                 -> key files in trust-backend/demo-keys/
 *   npm run seed:demo -- --public     -> also copies them to trust-dashboard/public/demo-keys/
 *                                        so the login page can offer one-click demo logins
 *                                        (only shown when NEXT_PUBLIC_DEMO_MODE=true).
 *
 * Never use --public on a real deployment: anyone could download those keys.
 */
import dotenv from "dotenv"
dotenv.config({ quiet: true })
import fs from "fs"
import path from "path"
import { hyperledgerService } from "../src/services/hyperledger.service"
import { userService, UserRole, UserStatus } from "../src/services/user.service"
import { generateEd25519KeyPair } from "../src/services/did.service"
import { dbMode } from "../src/lib/supabase"

const DEMO: Array<{ key: string; email: string; name: string; role: UserRole; status: UserStatus }> = [
  { key: "admin", email: "admin@trust.gov", name: "Chief Director Aravind (Admin)", role: "admin", status: "approved" },
  // A second administrator so lost-key recovery can reach its two-admin quorum in demos
  { key: "admin2", email: "admin2@trust.gov", name: "Deputy Director Kavya (Admin)", role: "admin", status: "approved" },
  { key: "investigator", email: "officer@trust.gov", name: "Officer Alex Vance", role: "investigator", status: "approved" },
  { key: "analyst", email: "analyst@trust.gov", name: "Dr. Elena Rostova", role: "analyst", status: "approved" },
  { key: "judiciary", email: "judge@trust.gov", name: "Judge Marcus Holloway", role: "judiciary", status: "approved" },
  { key: "auditor", email: "auditor@trust.gov", name: "Auditor Meera Krishnan", role: "auditor", status: "approved" },
  { key: "pending", email: "pending@trust.gov", name: "Cadet Rohan Sharma (Pending)", role: "investigator", status: "pending" },
  { key: "revoked", email: "revoked@trust.gov", name: "Analyst Vikram (Revoked)", role: "analyst", status: "revoked" }
]

async function main() {
  const outDir = path.join(__dirname, "..", "demo-keys")
  const publicDir = path.join(__dirname, "..", "..", "trust-dashboard", "public", "demo-keys")
  const copyPublic = process.argv.includes("--public")
  fs.mkdirSync(outDir, { recursive: true })
  if (copyPublic) fs.mkdirSync(publicDir, { recursive: true })
  console.log(`Seeding demo identities into ${dbMode} database...`)

  const index: Array<{ key: string; email: string; role: string; status: string; did: string }> = []
  for (const d of DEMO) {
    const file = path.join(outDir, `${d.key}.trustkey.json`)
    const existing = await userService.getUserByEmail(d.email)
    if (existing) {
      if (fs.existsSync(file)) {
        console.log(`  = ${d.email} already exists (${existing.did})`)
        if (copyPublic) fs.copyFileSync(file, path.join(publicDir, `${d.key}.trustkey.json`))
        index.push({ key: d.key, email: d.email, role: existing.role, status: existing.status, did: existing.did })
      } else {
        console.warn(`  ! ${d.email} exists but its key file is missing; skipping (delete the user to re-seed)`)
      }
      continue
    }
    const keys = generateEd25519KeyPair()
    const user = await userService.registerUser({
      email: d.email, displayName: d.name, publicKey: keys.publicKeyHex, authProvider: "key", forceRole: d.role, forceStatus: d.status
    })
    const keyFile = {
      format: "trust-did-key/1",
      did: user.did,
      email: user.email,
      publicKeyHex: keys.publicKeyHex,
      secretKeyHex: keys.privateKeyHex,
      createdAt: user.createdAt
    }
    fs.writeFileSync(file, JSON.stringify(keyFile, null, 2), { mode: 0o600 })
    if (copyPublic) fs.copyFileSync(file, path.join(publicDir, `${d.key}.trustkey.json`))
    index.push({ key: d.key, email: d.email, role: user.role, status: user.status, did: user.did })
    console.log(`  + ${d.email} -> ${user.did} [${user.role}/${user.status}]`)
  }
  if (copyPublic) {
    fs.writeFileSync(path.join(publicDir, "index.json"), JSON.stringify(index, null, 2))
    console.log(`Copied key files to ${publicDir} (set NEXT_PUBLIC_DEMO_MODE=true in the dashboard).`)
  }
  console.log(`Key files: ${outDir}`)
  await hyperledgerService.close()
  process.exit(0)
}

main().catch(err => {
  console.error(err)
  process.exit(1)
})
