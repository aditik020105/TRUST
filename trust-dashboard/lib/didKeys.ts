import nacl from "tweetnacl"

/**
 * Browser-side DID keys.
 *
 * The Ed25519 private key is generated here, stays in this browser (localStorage) and in the
 * key file the user downloads at sign-up. The server only ever receives the public key and
 * signatures. Losing the key file means the identity cannot sign in again; an admin must
 * revoke it and the user re-registers.
 */

export interface DidKeyFile {
  format: "trust-did-key/1"
  did: string
  email: string
  publicKeyHex: string
  /** 32-byte Ed25519 seed (hex). */
  secretKeyHex: string
  createdAt?: string
}

const toHex = (b: Uint8Array) => Array.from(b, x => x.toString(16).padStart(2, "0")).join("")
const fromHex = (h: string) => new Uint8Array((h.match(/../g) || []).map(x => parseInt(x, 16)))
const utf8 = (s: string) => new TextEncoder().encode(s)

/** Canonical payloads; keep in sync with trust-backend/src/services/did.service.ts (signingPayloads). */
export const signingPayloads = {
  login: (did: string, nonce: string) => `TRUST-LOGIN|${did}|${nonce}`,
  upload: (caseId: string, fileHash: string) => `TRUST-UPLOAD|${caseId}|${fileHash}`,
  status: (evidenceId: string, status: string) => `TRUST-STATUS|${evidenceId}|${status}`
}

export function generateKeyPair(): { publicKeyHex: string; secretKeyHex: string } {
  const seed = nacl.randomBytes(32)
  const kp = nacl.sign.keyPair.fromSeed(seed)
  return { publicKeyHex: toHex(kp.publicKey), secretKeyHex: toHex(seed) }
}

export function signWithKey(key: Pick<DidKeyFile, "secretKeyHex">, payload: string): string {
  const kp = nacl.sign.keyPair.fromSeed(fromHex(key.secretKeyHex))
  return toHex(nacl.sign.detached(utf8(payload), kp.secretKey))
}

export async function sha256Hex(data: Blob | ArrayBuffer): Promise<string> {
  if (!globalThis.crypto?.subtle) throw new Error("Web Crypto is unavailable: open the dashboard over https:// or http://localhost")
  const buf = data instanceof Blob ? await data.arrayBuffer() : data
  return toHex(new Uint8Array(await crypto.subtle.digest("SHA-256", buf)))
}

const storageKey = (did: string) => `trust_key_${did}`

export function saveKey(key: DidKeyFile): void {
  localStorage.setItem(storageKey(key.did), JSON.stringify(key))
}

export function loadKey(did: string): DidKeyFile | null {
  try {
    const raw = localStorage.getItem(storageKey(did))
    return raw ? parseKeyFile(raw) : null
  } catch {
    return null
  }
}

export function forgetKey(did: string): void {
  localStorage.removeItem(storageKey(did))
}

/** Validates a key file and checks that its secret key really produces its public key. */
export function parseKeyFile(text: string): DidKeyFile {
  let obj: Partial<DidKeyFile> & Record<string, unknown>
  try {
    obj = JSON.parse(text)
  } catch {
    throw new Error("Key file is not valid JSON")
  }
  if (obj?.format !== "trust-did-key/1" || typeof obj.did !== "string" || !/^[0-9a-f]{64}$/i.test(obj.secretKeyHex || "")) {
    throw new Error("Not a TRUST DID key file")
  }
  const derived = toHex(nacl.sign.keyPair.fromSeed(fromHex(String(obj.secretKeyHex))).publicKey)
  if (obj.publicKeyHex && derived !== String(obj.publicKeyHex).toLowerCase()) {
    throw new Error("Key file is corrupted: secret key does not match its public key")
  }
  return { ...(obj as DidKeyFile), publicKeyHex: derived }
}

export function downloadKeyFile(key: DidKeyFile): void {
  const blob = new Blob([JSON.stringify(key, null, 2)], { type: "application/json" })
  const url = URL.createObjectURL(blob)
  const a = document.createElement("a")
  a.href = url
  a.download = `${key.email.replace(/[^\w.-]/g, "_")}.trustkey.json`
  document.body.appendChild(a)
  a.click()
  a.remove()
  URL.revokeObjectURL(url)
}
