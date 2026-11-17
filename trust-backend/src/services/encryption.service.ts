import crypto from "crypto"
import fs from "fs"
import path from "path"

/**
 * AES-256-GCM encryption of evidence files before they reach storage.
 *
 * Blob layout: "TRUSTENC1" (9 bytes) | IV (12 bytes) | auth tag (16 bytes) | ciphertext
 * The evidence ID is bound as additional authenticated data, so an encrypted blob cannot
 * be swapped onto another evidence record without decryption failing.
 *
 * Key: EVIDENCE_ENCRYPTION_KEY = 32 random bytes as 64 hex chars or base64.
 * Without it (development only) a key is generated once and kept in $DATA_DIR/encryption.key.
 */

const MAGIC = Buffer.from("TRUSTENC1", "ascii")
const IV_LEN = 12
const TAG_LEN = 16
export const ENCRYPTION_ALG = "aes-256-gcm"

let cachedKey: Buffer | null = null

function parseKey(raw: string): Buffer {
  const s = raw.trim()
  const buf = /^[0-9a-fA-F]{64}$/.test(s) ? Buffer.from(s, "hex") : Buffer.from(s, "base64")
  if (buf.length !== 32) throw new Error("EVIDENCE_ENCRYPTION_KEY must decode to exactly 32 bytes (64 hex chars or base64)")
  return buf
}

function key(): Buffer {
  if (cachedKey) return cachedKey
  if (process.env.EVIDENCE_ENCRYPTION_KEY) {
    cachedKey = parseKey(process.env.EVIDENCE_ENCRYPTION_KEY)
    return cachedKey
  }
  if (process.env.NODE_ENV === "production") {
    throw new Error("EVIDENCE_ENCRYPTION_KEY is required in production")
  }
  const dir = process.env.DATA_DIR || path.join(process.cwd(), "data")
  const file = path.join(dir, "encryption.key")
  if (fs.existsSync(file)) {
    cachedKey = parseKey(fs.readFileSync(file, "utf-8"))
  } else {
    fs.mkdirSync(dir, { recursive: true })
    cachedKey = crypto.randomBytes(32)
    fs.writeFileSync(file, cachedKey.toString("hex"), { mode: 0o600 })
    console.warn(`[encryption] EVIDENCE_ENCRYPTION_KEY not set; generated a development key at ${file}`)
  }
  return cachedKey
}

/** For tests after changing env/DATA_DIR. */
export function resetEncryptionKeyCache(): void {
  cachedKey = null
}

export function encryptEvidence(plaintext: Buffer, evidenceId: string): Buffer {
  const iv = crypto.randomBytes(IV_LEN)
  const cipher = crypto.createCipheriv(ENCRYPTION_ALG, key(), iv)
  cipher.setAAD(Buffer.from(evidenceId, "utf-8"))
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()])
  return Buffer.concat([MAGIC, iv, cipher.getAuthTag(), ct])
}

export function isEncryptedBlob(blob: Buffer): boolean {
  return blob.length >= MAGIC.length + IV_LEN + TAG_LEN && blob.subarray(0, MAGIC.length).equals(MAGIC)
}

/** Throws if the blob was modified, belongs to another evidence ID, or the key is wrong. */
export function decryptEvidence(blob: Buffer, evidenceId: string): Buffer {
  if (!isEncryptedBlob(blob)) throw new Error("Stored object is not a TRUST AES-256-GCM blob")
  const iv = blob.subarray(MAGIC.length, MAGIC.length + IV_LEN)
  const tag = blob.subarray(MAGIC.length + IV_LEN, MAGIC.length + IV_LEN + TAG_LEN)
  const ct = blob.subarray(MAGIC.length + IV_LEN + TAG_LEN)
  const decipher = crypto.createDecipheriv(ENCRYPTION_ALG, key(), iv)
  decipher.setAAD(Buffer.from(evidenceId, "utf-8"))
  decipher.setAuthTag(tag)
  return Buffer.concat([decipher.update(ct), decipher.final()])
}
