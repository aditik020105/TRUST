/**
 * Break-glass: re-approve an account as admin (e.g. if the only admin was revoked by the
 * firewall). Run on the server; the change is recorded on the ledger as a system action.
 *
 *   npm run admin:restore -- someone@agency.gov
 */
import dotenv from "dotenv"
dotenv.config({ quiet: true })
import { hyperledgerService } from "../src/services/hyperledger.service"
import { userService, SYSTEM_DID } from "../src/services/user.service"

async function main() {
  const email = process.argv[2]
  if (!email) throw new Error("usage: npm run admin:restore -- <email>")
  const user = await userService.getUserByEmail(email)
  if (!user) throw new Error(`No account for ${email}`)
  const updated = await userService.updateUserAuthorization({
    uid: user.uid, status: "approved", role: "admin", adminDid: SYSTEM_DID, reason: "break-glass admin restore (CLI)"
  })
  console.log(`${updated!.email} is now ${updated!.role}/${updated!.status}; ledger tx ${updated!.txHash}`)
  await hyperledgerService.close()
  process.exit(0)
}

main().catch(err => {
  console.error(err.message || err)
  process.exit(1)
})
