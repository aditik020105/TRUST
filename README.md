# TRUST: Tamper-Proof Chain of Custody

Chain-of-custody platform for digital evidence. Every action is tied to a W3C DID (an Ed25519 key that never leaves the user's browser), checked by an OPA policy and a case-access check, and committed to a Hyperledger Fabric ledger, endorsed by two of the three agencies, before it takes effect. Files are encrypted with AES-256-GCM and stored off-chain; sensitive case notes live only in a Fabric private data collection.

```
Browser (Next.js)                       Express gateway                                    Stores
 ─ Ed25519 key in localStorage          1 CORS + security headers                          Supabase Postgres (or local JSON)
 ─ signs login nonce, uploads,  ──────► 2 firewall (Redis-shared; 3 jails = DID revoked)    Supabase Storage, AES-256-GCM (or disk)
   status changes                       3 session JWT (expires) + live identity registry   Hyperledger Fabric: Police, Forensics,
 ─ SHA-256 in browser                   4 OPA role policy  +  case access / delegation       Judiciary peers, 2-of-3 endorsement,
                                        5 controllers ── 6 ledger FIRST, then DB             private collection for case notes
                                                         └─ audit row → webhook outbox      (or local hash-chained file)
```

Architecture and design rationale: [SYSTEM_ARCHITECTURE.md](./SYSTEM_ARCHITECTURE.md). Viva questions and answers: [VIVA_AND_ARCHITECTURE_GUIDE.md](./VIVA_AND_ARCHITECTURE_GUIDE.md).

## Features and where they live (trust-backend/src unless noted)

| Feature | Where |
| --- | --- |
| DID identity, keys generated and kept in the browser | `trust-dashboard/lib/didKeys.ts`, `services/did.service.ts` |
| Challenge-response login, expiring session JWT, optional Firebase factor | `controllers/auth.controller.ts`, `services/auth.service.ts` |
| Role policy with separation of duties (Rego + identical embedded evaluator) | `policies/trust_authz.rego`, `services/opa.service.ts` |
| Case-scoped access, time-bound delegation (grant/revoke/expiry on ledger) | `services/case-access.service.ts`, Cases page |
| Signed uploads and status changes; AES-256-GCM bound to evidence ID | `controllers/evidence.controller.ts`, `services/encryption.service.ts` |
| Ledger-first custody events; view/download fail closed | `evidence.controller.ts` |
| Chaincode (shared rules), private data collection for case notes | `trust-chaincode/`, `ledger/evidence-logic.ts` |
| Multi-org Fabric gateway: each action submitted as the acting agency | `ledger/fabric-ledger.ts` |
| Custody verification (file vs ledger, DB vs ledger, signatures, audit rows) | `GET /api/evidence/:id/verify` |
| Courtroom report: PDF + JSON, hash on ledger, signed by gateway | `GET /api/evidence/:id/report`, `services/report.service.ts` |
| Lost-key recovery approved by 2 different admins; DID history keeps old signatures valid | `services/recovery.service.ts`, login page, Admin → Key Recovery |
| Adaptive firewall, Redis-shared across instances; 3 jails revoke the DID | `middleware/ddos.middleware.ts`, `middleware/firewall-store.ts` |
| DB-vs-ledger reconciliation (every 10 min + on demand); delegation expiry sweep | `services/reconciliation.service.ts` |
| Legacy logbook import (CSV → attested ledger events) | `services/legacy-import.service.ts`, Admin → Legacy Import |
| Case-management connector: HMAC-signed webhook with retry outbox; custody JSON pull API | `services/audit-row.service.ts`, `GET /api/cases/:id/custody` |
| Backup, restore with manifest check + reconciliation | `services/backup.service.ts`, `npm run backup`, `npm run restore` |

## Quick start (no cloud accounts)

```bash
cd trust-backend && npm install && cp .env.example .env
npm run gen:secrets            # paste the lines into .env
npm run seed:demo -- --public  # demo accounts + key files (local demo only)
npm run dev                    # http://localhost:3001

cd ../trust-dashboard && npm install && cp .env.example .env.local
# NEXT_PUBLIC_DEMO_MODE=true for one-click demo logins
npm run dev                    # http://localhost:3000
```

Without Supabase, Fabric or Redis settings the backend uses `data/db.json`, `storage/`, a hash-chained `data/ledger.json` and in-memory firewall counters. The same controllers, policy and contract rules run in every mode.

## Production setup

**1. Supabase.** Create a project. SQL Editor → paste `supabase/schema.sql` → Run (it is idempotent and was validated on Postgres 17). Put the Project URL and the `service_role` key in `trust-backend/.env` as `SUPABASE_URL` and `SUPABASE_SERVICE_KEY`. The startup log prints `database: supabase` or lists what is missing. The service-role key must never go into the dashboard.

**2. Hyperledger Fabric (three agencies).** Download the Fabric 2.5 binaries, then:

```bash
curl -sSLO https://github.com/hyperledger/fabric/releases/download/v2.5.12/hyperledger-fabric-linux-amd64-2.5.12.tar.gz
mkdir -p ~/fabric && tar xzf hyperledger-fabric-linux-amd64-2.5.12.tar.gz -C ~/fabric   # macOS: darwin-arm64 / darwin-amd64
cd trust-chaincode && npm install && cd ..
FABRIC_HOME=~/fabric ./fabric/multi-org/start-network.sh      # later runs resume the same ledger; --fresh starts over
./fabric/multi-org/stop-network.sh
```

This runs (no Docker) a Raft orderer, one peer each for PoliceOrgMSP, ForensicsOrgMSP and JudiciaryOrgMSP, a client-only AdminOrgMSP, the channel `evidence-channel`, the chaincode with endorsement policy `OutOf(2, Police, Forensics, Judiciary)` and the private collection `evidencePrivateDetails` (Police and Judiciary only). Put the two printed lines (`LEDGER_MODE=fabric`, `FABRIC_ORGS_FILE=…`) in `.env`. Check the network with `npm run fabric:check`, which proves 2-of-3 endorsement and that the Forensics peer cannot read private notes. Single-org alternatives: `fabric/native/` (no Docker) and `fabric/deploy-test-network.sh` (fabric-samples + Docker).

**3. Redis (several backend instances).** Set `REDIS_URL`. Rate-limit windows, jails and firewall logs are then shared; each request is one atomic Lua script.

**4. Firebase (optional).** `NEXT_PUBLIC_FIREBASE_*` in the dashboard and the same project as `FIREBASE_PROJECT_ID` in the backend. Accounts then need the password and the DID key.

**5. Other settings** (all in `.env.example`): `ADMIN_EMAILS` (first admin), `REPORT_SIGNING_KEY`, `CASE_ACCESS_MODE`, `RECOVERY_APPROVALS`, `CASE_MGMT_WEBHOOK_URL`/`_SECRET`, `CORS_ORIGINS`.

## Accounts, keys and recovery

- Sign-up generates the key in the browser and downloads `<email>.trustkey.json`; the server stores only the public key. New accounts are pending until an admin approves them. The first sign-up whose email is in `ADMIN_EMAILS` becomes the approved admin.
- Other browser: "Sign in with a key file". Lost key: "Lost your key file?" on the login page generates a new key and files a request; two different administrators approve it under Admin → Key Recovery after confirming the person's identity. The DID then rotates; evidence signed with the old key still verifies.
- Locked out of admin entirely: `npm run admin:restore -- <email>` on the server (recorded on the ledger).

## Testing and tools (trust-backend)

| Command | What it does |
| --- | --- |
| `npm test` | 113 Jest/Supertest tests (local ledger, in-memory firewall), plus 4 Redis tests when `REDIS_TEST_URL` is set |
| `TEST_LEDGER_MODE=fabric FABRIC_ORGS_FILE=… REDIS_TEST_URL=redis://… npx jest --runInBand --testPathIgnorePatterns ledger.test /support/` | the API suites (111 tests) against a live Fabric network and Redis |
| `npm run fabric:check` | endorsement, submitting-org and private-data checks on the multi-org network |
| `npm run opa:parity` | embedded evaluator vs a running OPA server (630 combinations) |
| `npm run bench` (`BENCH_LEDGER=fabric`) | latency/throughput table → `bench-results/` |
| `npm run backup` / `npm run restore -- <dir>` | backup with SHA-256 manifest; restore into an empty DB, then reconcile against the ledger |
| `npm run seed:demo`, `npm run admin:restore`, `npm run gen:secrets` | demo data, break-glass admin, fresh secrets |

Measured on the three-agency network (20 runs, 2-core VM, `BatchTimeout` 200 ms): ledger commit p50 232 ms; upload 249 ms; audited view 242 ms; judicial verify 243 ms; full custody verification 266 ms; login 6 ms; list 3 ms; 339 req/s for listing with 10 concurrent clients. Commit time is dominated by the orderer's batch timeout.

## Limits to state honestly

- The bundled networks run every organisation on one machine; a real deployment runs each agency's peer on its own infrastructure and certificate authority (cryptogen is for development).
- Private keys sit in browser localStorage, so an XSS bug in the dashboard could expose them. Evidence is never rendered as HTML/SVG in the dashboard's origin for this reason.
- Legacy-imported entries are attested by the importing admin, not signed by the original officers, and are labelled as such.
- In `LEDGER_MODE=local` the ledger is a single tamper-evident file controlled by the backend: it detects edits but gives no distributed trust.
