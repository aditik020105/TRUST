# TRUST system architecture

TRUST records who handled each piece of digital evidence, when, and with what result, so that a court can check the record without trusting any single database or administrator. This document describes how the implemented system does that.

## 1. Components

| Layer | Component | Technology |
| --- | --- | --- |
| Client | Dashboard | Next.js 16, React 19; Ed25519 keys via tweetnacl; SHA-256 via Web Crypto |
| Gateway | REST API | Node 18+, Express 5, TypeScript |
| Identity | DID registry, session tokens | `did:trust` method, Ed25519; HS256 JWT; optional Firebase ID tokens |
| Policy | Role policy | Open Policy Agent (Rego v1) or the embedded evaluator (verified identical) |
| Case access | Ownership and delegation | `case-access.service.ts` |
| Ledger | Permissioned ledger | Hyperledger Fabric 2.5 (Gateway API), TypeScript chaincode; local hash-chained file for development |
| Database | Index and metadata | Supabase Postgres (local JSON emulator for development) |
| Files | Evidence blobs | Supabase Storage (private bucket) or disk; AES-256-GCM |
| Firewall state | Rate-limit windows, jails | Redis (shared) or in-memory |
| Integration | Case-management systems | Signed webhook outbox; custody JSON export |

## 2. Fabric network

| Organisation | Role in the network | Peer |
| --- | --- | --- |
| PoliceOrgMSP | investigators | peer0.police (7051) |
| ForensicsOrgMSP | forensic analysts | peer0.forensics (8051) |
| JudiciaryOrgMSP | judges, auditors | peer0.judiciary (9051) |
| AdminOrgMSP | consortium administrators (client-only) | none |
| OrdererMSP | Raft ordering service | orderer (7050) |

- **Endorsement policy:** `OutOf(2, Police, Forensics, Judiciary)`. A custody event is valid only if two agencies' peers executed the contract and agreed on its result, so no single agency can write history alone.
- **Lifecycle:** the chaincode definition needs approval from a majority of organisations; all three agencies approve it.
- **Private data collection** `evidencePrivateDetails`: members Police, Judiciary and Admin; `memberOnlyRead`. The case notes and original file name exist only on Police and Judiciary peers; every peer and every block holds only their SHA-256. Writes with private data are endorsed only by member peers.
- **Gateway identities:** the backend holds one client identity per organisation and submits each action as the acting user's agency (`submitterMspId` in the ledger record).
- **Chaincode-as-a-service:** the contract runs as a Node process the peers connect to; no Docker is needed.

## 3. Contract (chaincode) rules

The rules live in `trust-backend/src/ledger/evidence-logic.ts`, copied verbatim into `trust-chaincode/` (a test fails if the copies differ). The local ledger runs the same functions.

| Function | Effect | Rules enforced |
| --- | --- | --- |
| `CreateEvidence` | evidence record + "uploaded" audit record in one transaction; optional private details | 64-hex SHA-256, 64-byte signature, `did:trust:` uploader, ID not already used |
| `UpdateEvidenceStatus` | new status + "status_*" audit record | evidence exists, valid status, not already in that status |
| `RecordAuditAccess` | any other custody or identity event | unique log ID, `did:trust:` performer |
| `ReadEvidence`, `ReadEvidencePrivate`, `ReadAudit`, `ListAudit`, `ListEvidence` | queries | private read only on member peers |

Keys: `EVIDENCE_<id>`, `AUDIT_<logId>`. Every record stores its transaction ID and the submitting MSP.

## 4. Request pipeline

1. **Headers:** CORS allow-list, `nosniff`, `X-Frame-Options: DENY`, no referrer.
2. **Firewall:** sliding window (30 requests / 10 s → HTTP 429; above 50 → 30 s jail). Each jail counts as a warning against the authenticated user (identified only from a verified token); three warnings revoke the DID through the registry, which is a ledger event. With Redis, every backend instance shares the same counters through one atomic script per request.
3. **Identity:** HS256 session JWT (issuer, audience, expiry checked). Role and status are then read from the registry on every request, so approvals and revocations take effect immediately.
4. **Policy:** OPA decides by role, status and action (Table below). Denials return HTTP 403 with `X-OPA-Decision` and `X-OPA-Rule`.
5. **Case access:** for evidence routes, the case-access service checks that the caller owns the case, holds an active delegation, or has an oversight role.
6. **Controller → ledger → database:** the ledger transaction is committed first; the database row (with the transaction ID and block number) is written after. If the ledger is unreachable, nothing changes and file access is refused.

### Role policy

| Action | Investigator | Analyst | Judiciary | Auditor | Admin |
| --- | --- | --- | --- | --- | --- |
| list / view / download / verify / court report / audit log | yes | yes | yes | yes | yes |
| upload evidence | yes | yes | no | no | yes |
| flag (status flagged/pending) | no | yes | yes | no | yes |
| verify (status verified) | no | no | yes | no | yes |
| read private case notes | yes | no | yes | no | yes |
| delegate case access (owner only) | yes | yes | no | no | yes |
| approve / revoke users, recovery, firewall, legacy import | no | no | no | no | yes |
| policy viewer, ledger status, reconciliation | no | no | no | yes | yes |

Pending or revoked accounts are denied every action.

### Case access

Investigators and analysts see a case only if they opened it (first upload) or hold an active delegation; judges, auditors and admins can read every case. Owners and admins grant `read` or `contribute` access to a DID for 1–720 hours. Grants, revocations and expiries are ledger events; expiry is enforced at request time and recorded by a sweep within a minute. Ownership follows the person through key recovery. `CASE_ACCESS_MODE=open` disables case scoping.

## 5. Flows

**Registration.** The browser generates an Ed25519 key pair and sends only the public key (plus a Firebase ID token when Firebase is enabled). The gateway builds the DID Document (`did:trust:<role>:<fingerprint>`), records the registration on the ledger, and stores the account as pending. The browser downloads the key file.

**Login.** `POST /api/auth/challenge` returns a one-time nonce (2 minutes, single use). The browser signs `TRUST-LOGIN|<did>|<nonce>`; `POST /api/auth/verify` checks the signature against the DID Document (and the Firebase token if required) and issues a session JWT (default 60 minutes).

**Upload.** The browser hashes the file and signs `TRUST-UPLOAD|<case>|<sha256>`. The gateway recomputes the hash, verifies the signature, checks case access, encrypts the file (AES-256-GCM, evidence ID as associated data), stores it, opens the case if new (ledger event), commits `CreateEvidence` (with private notes as transient data), then writes the database rows. If the ledger refuses, the stored blob is deleted.

**View / download.** The access is committed to the ledger before the blob is read. The blob must decrypt (authentication tag) and match the recorded hash before any byte is released.

**Status change.** Signed `TRUST-STATUS|<id>|<status>`; ledger first (`UpdateEvidenceStatus`), then the database.

**Custody verification.** Reads the ledger record itself (not the database copy) and checks: anchored; database row equals ledger; ciphertext authentic; file hash equals ledger hash; uploader signature valid (resolving retired DIDs); private notes match their on-chain hash; every audit row matches its ledger transaction and no ledger event is missing from the database; local hash chain intact. The check is itself a ledger event.

**Court report.** The verification plus the full timeline and the uploader's DID Document, as canonical JSON and as a PDF. Its SHA-256 is written to the ledger (`report_exported`) and signed with the gateway's Ed25519 report key (`GET /api/report-key`).

**Key recovery.** The user generates a new key and files a request. A configurable number (default two) of distinct administrators, none of them the subject, must approve. On quorum the DID rotates; the old DID Document moves to the account's history so old signatures verify, and sessions for the old DID stop working.

**Reconciliation.** Every 10 minutes and on demand: every database audit row and evidence row is compared with the ledger, in both directions. A restored or edited database shows up here.

**Connector.** Each audit row is queued in `webhook_outbox` and POSTed to `CASE_MGMT_WEBHOOK_URL` with `X-Trust-Signature: sha256=<HMAC>`; failures retry with exponential backoff. External systems can also pull `GET /api/cases/:caseId/custody`.

**Legacy import.** CSV rows from pre-TRUST logbooks become ledger events attested by the importing administrator, plus a batch event carrying the file's SHA-256.

## 6. Data model (Supabase)

`users` (public keys, DID Document, DID history, status), `evidence` (hash, uploader signature, encryption, tx hash, block), `audit_log` (append-only by trigger), `cases`, `case_access`, `recovery_requests`, `webhook_outbox`, and the private `evidence-files` bucket. RLS is enabled with no policies, so only the service-role key used by the backend can access them. See `supabase/schema.sql`.

## 7. Threats and mitigations

| Threat | Mitigation |
| --- | --- |
| Edited database row | Verification and reconciliation compare it with the ledger record |
| Edited or swapped file | AES-GCM tag and hash check fail before release |
| Silent inspection | Views and downloads are committed to the ledger first; ledger failure blocks access |
| One agency rewriting history | 2-of-3 endorsement across agencies |
| Impersonation / stolen password | Login requires a signature from the DID key; tokens are signed and expire |
| Server compromise exposing keys | Private keys never reach the server |
| Single admin taking over an identity | Recovery needs distinct administrators |
| Leak of witness details to other agencies | Private data collection; policy also blocks analysts and auditors |
| Privilege escalation | OPA role policy and case-access checks on every route |
| Floods, spread across instances | Redis-shared limiter; repeat abuse revokes the DID |
| Stale restored backup | Restore always runs reconciliation against the ledger |
