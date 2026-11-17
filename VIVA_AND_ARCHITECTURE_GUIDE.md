# Viva guide: likely questions and answers

Short, accurate answers about what the implemented system does. Numbers come from the test suites and benchmark in this repository.

## Demo script (about 10 minutes)

1. `FABRIC_HOME=~/fabric ./fabric/multi-org/start-network.sh`, then `npm run fabric:check` in `trust-backend`: shows a transaction endorsed by two agencies and the Forensics peer failing to read private notes.
2. `npm run seed:demo -- --public`, backend with `LEDGER_MODE=fabric`, dashboard with `NEXT_PUBLIC_DEMO_MODE=true`.
3. officer@trust.gov uploads to a new case with private notes; the receipt shows the transaction and block.
4. analyst@trust.gov cannot see the case. The officer delegates "contribute" for 24 h on the Cases page; the analyst now sees it, runs Verify integrity, and has no Private notes button.
5. judge@trust.gov reads the private notes, downloads the court report, marks the evidence verified.
6. Lost key: on the login page, request recovery for officer@trust.gov; approve as admin@ and admin2@ in Admin → Key Recovery; sign in with the new key file.
7. Admin → Ledger: run reconciliation ("Database and ledger agree"). Edit a row in the database file and run it again to show the mismatch.

## Questions

**Why a permissioned ledger and not Ethereum?** The parties to a case are known agencies. Fabric gives each agency its own peer and identity, an endorsement policy that requires agreement between agencies, and private data collections for information only some agencies may see. A public chain would expose custody metadata and gives no notion of agency membership.

**What stops one agency from rewriting history?** The endorsement policy `OutOf(2, Police, Forensics, Judiciary)`: a transaction is valid only if two agencies' peers executed it and produced the same result. `npm run fabric:check` shows the endorsing organisations of real transactions.

**What exactly is on the ledger?** Evidence hash, case ID, uploader DID and signature, status, and every custody event (who, what, when, transaction ID). Never the file. Case notes are in a private data collection; the block holds only their hash.

**Where are private keys?** Only in the user's browser and the key file they download. The server stores public keys; there is no server-side signing.

**How does login work?** The server issues a one-time nonce; the browser signs it with the DID key; the server verifies the signature against the DID Document and issues a session JWT that expires (60 minutes by default). Role and approval status are re-read from the registry on every request.

**What if someone loses their key?** They generate a new key and file a recovery request. Two different administrators, neither of them the person themselves, must approve after confirming identity out of band. The DID then rotates; the old DID Document is kept so evidence signed earlier still verifies.

**How is time-bound access implemented?** Session tokens expire, and case access is delegated for 1–720 hours. A delegation's grant, revocation and expiry are all ledger events; expiry is enforced on every request.

**What happens if the ledger is down?** Nothing changes: uploads, status changes and file views are refused (HTTP 502). No evidence is viewed without a ledger record.

**How do you detect a tampered database?** Custody verification compares the database row with the ledger record itself, recomputes the file hash and checks every audit row against its transaction. Reconciliation runs every 10 minutes over the whole database.

**What does the court receive?** A PDF and a canonical JSON report with the verification results, the full timeline and the uploader's DID Document. The report's SHA-256 is written to the ledger and signed by the gateway, so any later edit is detectable.

**What does OPA do, and why separate it?** It decides what each role may do. The rules are one readable file (`trust_authz.rego`) instead of being scattered through controllers. The embedded evaluator was compared with a real OPA server on 630 role/status/action combinations with no differences.

**Separation of duties?** Investigators collect but cannot verify; analysts can flag but not verify; judges verify but cannot upload; auditors read only; only admins manage accounts.

**How does the firewall work across several servers?** Counters live in Redis; each request runs one atomic Lua script, so two instances cannot both let a client through. Three flood jails revoke the user's DID.

**How is the system tested?** 113 automated tests locally (plus 4 Redis tests), and 111 API tests run against the live three-agency Fabric network with Redis. Includes negative tests: forged and expired tokens, wrong-key signatures, replayed challenges, edited files and rows, forged audit rows, ledger outages, stale backups.

**Performance?** On the three-agency network on a 2-core VM: ledger commit p50 232 ms, upload 249 ms, audited view 242 ms, login 6 ms. Commit time is dominated by the orderer's 200 ms batch timeout.

**Limitations?** The bundled network runs all organisations on one machine with cryptogen certificates; production needs each agency's own infrastructure and CA. Keys in browser storage are exposed to any XSS bug. Legacy-imported entries are attested by an admin, not signed by the original officers. Authenticity of the evidence content itself remains a matter for forensic examination.
