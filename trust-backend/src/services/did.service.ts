import crypto from "crypto"

/**
 * did:trust method helpers.
 *
 * Private keys never reach the server: the browser generates an Ed25519 keypair,
 * keeps the private key, and registers only the public key. The server builds the
 * W3C DID Document from that public key and verifies signatures against it.
 */

export interface VerificationMethod {
  id: string
  type: "Ed25519VerificationKey2020"
  controller: string
  publicKeyPem: string
  publicKeyHex: string
  fingerprint: string
}

export interface DIDDocument {
  "@context": string[]
  id: string
  controller: string
  verificationMethod: VerificationMethod[]
  authentication: string[]
  assertionMethod: string[]
  service: Array<{ id: string; type: string; serviceEndpoint: string }>
  metadata: {
    role: string
    mspId: string
    status: "approved" | "pending" | "revoked"
    created: string
    updated: string
    ledgerTxHash?: string
  }
}

export interface DIDIdentity {
  did: string
  publicKeyHex: string
  publicKeyPem: string
  fingerprint: string
  document: DIDDocument
}

// DER prefix for an Ed25519 SubjectPublicKeyInfo (RFC 8410) followed by the 32-byte key.
const ED25519_SPKI_PREFIX = Buffer.from("302a300506032b6570032100", "hex")

/** Accepts a raw 32-byte key (hex), SPKI DER (hex) or PEM; returns an Ed25519 KeyObject. */
export function parseEd25519PublicKey(input: string): crypto.KeyObject {
  if (typeof input !== "string" || !input.trim()) throw new Error("publicKey is required")
  const s = input.trim()
  let key: crypto.KeyObject
  try {
    key = toKeyObject(s)
  } catch (err: any) {
    throw new Error(`publicKey is not a valid Ed25519 public key (${err.message})`)
  }
  if (key.asymmetricKeyType !== "ed25519") throw new Error("publicKey must be an Ed25519 key")
  return key
}

function toKeyObject(s: string): crypto.KeyObject {
  let key: crypto.KeyObject
  if (s.includes("BEGIN PUBLIC KEY")) {
    key = crypto.createPublicKey(s)
  } else if (/^[0-9a-fA-F]{64}$/.test(s)) {
    key = crypto.createPublicKey({ key: Buffer.concat([ED25519_SPKI_PREFIX, Buffer.from(s, "hex")]), format: "der", type: "spki" })
  } else if (/^[0-9a-fA-F]+$/.test(s)) {
    key = crypto.createPublicKey({ key: Buffer.from(s, "hex"), format: "der", type: "spki" })
  } else {
    throw new Error("publicKey must be a 32-byte hex Ed25519 key, SPKI DER hex, or PEM")
  }
  return key
}

export function rawPublicKeyHex(key: crypto.KeyObject): string {
  const der = key.export({ type: "spki", format: "der" }) as Buffer
  return der.subarray(der.length - 32).toString("hex")
}

export function buildDidIdentity(params: {
  publicKey: string
  role: string
  mspId: string
  status: "approved" | "pending" | "revoked"
  ledgerTxHash?: string
}): DIDIdentity {
  const key = parseEd25519PublicKey(params.publicKey)
  const der = key.export({ type: "spki", format: "der" }) as Buffer
  const publicKeyPem = key.export({ type: "spki", format: "pem" }).toString()
  const publicKeyHex = rawPublicKeyHex(key)
  const fingerprint = crypto.createHash("sha256").update(der).digest("hex").slice(0, 16)
  const role = (params.role || "investigator").toLowerCase().replace(/[^a-z0-9]/g, "")
  const did = `did:trust:${role}:${fingerprint}`
  const keyId = `${did}#keys-1`
  const now = new Date().toISOString()

  return {
    did,
    publicKeyHex,
    publicKeyPem,
    fingerprint,
    document: {
      "@context": ["https://www.w3.org/ns/did/v1", "https://w3id.org/security/suites/ed25519-2020/v1"],
      id: did,
      controller: did,
      verificationMethod: [{ id: keyId, type: "Ed25519VerificationKey2020", controller: did, publicKeyPem, publicKeyHex, fingerprint }],
      authentication: [keyId],
      assertionMethod: [keyId],
      service: [
        { id: `${did}#fabric-msp`, type: "HyperledgerFabricMSP", serviceEndpoint: params.mspId },
        { id: `${did}#opa-policy`, type: "OpenPolicyAgentGuard", serviceEndpoint: "trust.authz" }
      ],
      metadata: { role: params.role, mspId: params.mspId, status: params.status, created: now, updated: now, ledgerTxHash: params.ledgerTxHash }
    }
  }
}

export function verifyWithDocument(
  doc: DIDDocument | null | undefined,
  payload: string,
  signatureHex: string
): { verified: boolean; did?: string; keyId?: string; publicKeyFingerprint?: string; reason: string } {
  if (!doc || !doc.verificationMethod?.length) return { verified: false, reason: "DID Document not found" }
  if (typeof signatureHex !== "string" || !/^[0-9a-fA-F]{128}$/.test(signatureHex)) {
    return { verified: false, did: doc.id, reason: "signature must be a 64-byte Ed25519 signature in hex" }
  }
  const vm = doc.verificationMethod[0]
  try {
    const ok = crypto.verify(null, Buffer.from(payload, "utf-8"), crypto.createPublicKey(vm.publicKeyPem), Buffer.from(signatureHex, "hex"))
    return {
      verified: ok,
      did: doc.id,
      keyId: vm.id,
      publicKeyFingerprint: vm.fingerprint,
      reason: ok ? "Ed25519 signature verified against the DID Document" : "Signature does not match payload for this DID"
    }
  } catch (err: any) {
    return { verified: false, did: doc.id, reason: `Verification error: ${err.message}` }
  }
}

/** Key generation for scripts and tests only. The application never stores the private key. */
export function generateEd25519KeyPair(): { publicKeyHex: string; privateKeyPem: string; privateKeyHex: string } {
  const { publicKey, privateKey } = crypto.generateKeyPairSync("ed25519")
  const pkcs8 = privateKey.export({ type: "pkcs8", format: "der" }) as Buffer
  return {
    publicKeyHex: rawPublicKeyHex(publicKey),
    privateKeyPem: privateKey.export({ type: "pkcs8", format: "pem" }).toString(),
    // 32-byte seed, the format tweetnacl/browser code expects (nacl secretKey = seed || publicKey)
    privateKeyHex: pkcs8.subarray(pkcs8.length - 32).toString("hex")
  }
}

export function signWithPrivateKeyPem(privateKeyPem: string, payload: string): string {
  return crypto.sign(null, Buffer.from(payload, "utf-8"), crypto.createPrivateKey(privateKeyPem)).toString("hex")
}

/** Canonical strings that clients sign. Keep in sync with trust-dashboard/lib/didKeys.ts. */
export const signingPayloads = {
  login: (did: string, nonce: string) => `TRUST-LOGIN|${did}|${nonce}`,
  upload: (caseId: string, fileHash: string) => `TRUST-UPLOAD|${caseId}|${fileHash}`,
  status: (evidenceId: string, status: string) => `TRUST-STATUS|${evidenceId}|${status}`
}
