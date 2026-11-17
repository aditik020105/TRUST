import crypto from "crypto"
import fs from "fs"
import path from "path"
import PDFDocument from "pdfkit"

/**
 * Courtroom export.
 *
 * The report is a JSON bundle (machine-checkable) and a PDF rendering of the same content.
 * Integrity of the report itself is protected twice:
 *   1. reportHash = SHA-256 of the canonical JSON bundle; it is written to the ledger in the
 *      "report_exported" event, so anyone with ledger access can confirm the report is unaltered.
 *   2. The gateway signs reportHash with its Ed25519 report key (public key: GET /api/report-key).
 */

let signingKey: crypto.KeyObject | null = null

function reportKey(): crypto.KeyObject {
  if (signingKey) return signingKey
  if (process.env.REPORT_SIGNING_KEY) {
    signingKey = crypto.createPrivateKey(Buffer.from(process.env.REPORT_SIGNING_KEY, "base64").toString("utf-8"))
    return signingKey
  }
  const dir = process.env.DATA_DIR || path.join(process.cwd(), "data")
  const file = path.join(dir, "report-signing-key.pem")
  if (!fs.existsSync(file)) {
    if (process.env.NODE_ENV === "production") throw new Error("REPORT_SIGNING_KEY is required in production")
    fs.mkdirSync(dir, { recursive: true })
    const { privateKey } = crypto.generateKeyPairSync("ed25519")
    fs.writeFileSync(file, privateKey.export({ type: "pkcs8", format: "pem" }), { mode: 0o600 })
  }
  signingKey = crypto.createPrivateKey(fs.readFileSync(file, "utf-8"))
  return signingKey
}

export function reportPublicKeyPem(): string {
  return crypto.createPublicKey(reportKey()).export({ type: "spki", format: "pem" }).toString()
}

/** Deterministic JSON (sorted keys) so the hash is reproducible by anyone. */
export function canonicalJson(value: any): string {
  if (value === null || typeof value !== "object") return JSON.stringify(value)
  if (Array.isArray(value)) return `[${value.map(canonicalJson).join(",")}]`
  return `{${Object.keys(value).filter(k => value[k] !== undefined).sort().map(k => `${JSON.stringify(k)}:${canonicalJson(value[k])}`).join(",")}}`
}

export interface ReportBody {
  format: "trust-custody-report/1"
  generatedAt: string
  generatedBy: { did: string; role: string; mspId: string }
  evidence: Record<string, any>
  verdict: { verified: boolean; failedChecks: string[] }
  checks: Array<{ name: string; ok: boolean; detail: string }>
  ledgerRecord: any
  ledger: { mode: string; channel: string; chaincode: string }
  custodyTimeline: Array<Record<string, any>>
  uploaderDidDocument: any
}

export function sealReport(body: ReportBody) {
  const reportHash = crypto.createHash("sha256").update(canonicalJson(body)).digest("hex")
  const signature = crypto.sign(null, Buffer.from(reportHash, "utf-8"), reportKey()).toString("hex")
  return { reportHash, gatewaySignature: signature }
}

export function verifySealedReport(body: ReportBody, reportHash: string, signatureHex: string): boolean {
  const h = crypto.createHash("sha256").update(canonicalJson(body)).digest("hex")
  if (h !== reportHash) return false
  return crypto.verify(null, Buffer.from(reportHash, "utf-8"), crypto.createPublicKey(reportKey()), Buffer.from(signatureHex, "hex"))
}

export function renderReportPdf(body: ReportBody, seal: { reportHash: string; gatewaySignature: string; exportTx: string; exportBlock: number }): Promise<Buffer> {
  return new Promise((resolve, reject) => {
    const doc = new PDFDocument({ size: "A4", margin: 48, info: { Title: `Chain of custody report ${body.evidence.id}`, Author: "TRUST" } })
    const chunks: Buffer[] = []
    doc.on("data", c => chunks.push(c))
    doc.on("end", () => resolve(Buffer.concat(chunks)))
    doc.on("error", reject)

    const mono = (t: string, size = 8) => doc.font("Courier").fontSize(size).text(t, { lineBreak: true })
    const label = (k: string, v: string) => {
      // long unbroken values (hashes, signatures) go on their own line in monospace so they wrap
      if (v && v.length > 70 && !v.includes(" ")) {
        doc.font("Helvetica-Bold").fontSize(9).text(`${k}:`)
        mono(v, 7.5)
        return
      }
      doc.font("Helvetica-Bold").fontSize(9).text(`${k}: `, { continued: !!v })
      if (v) doc.font("Helvetica").text(v)
    }
    const heading = (t: string) => {
      doc.moveDown(0.8).font("Helvetica-Bold").fontSize(12).fillColor("#111").text(t)
      doc.moveTo(doc.x, doc.y + 2).lineTo(doc.page.width - 48, doc.y + 2).strokeColor("#999").lineWidth(0.5).stroke().moveDown(0.4)
    }

    doc.font("Helvetica-Bold").fontSize(18).text("Chain of Custody Report")
    doc.font("Helvetica").fontSize(10).fillColor("#444").text(`Evidence ${body.evidence.id} · Case ${body.evidence.caseId}`)
    doc.text(`Generated ${body.generatedAt} by ${body.generatedBy.did} (${body.generatedBy.role}, ${body.generatedBy.mspId})`).fillColor("#111")

    doc.moveDown(0.6)
    const v = body.verdict.verified
    doc.rect(doc.x, doc.y, doc.page.width - 96, 34).fillAndStroke(v ? "#e7f6ee" : "#fdecec", v ? "#2f855a" : "#c53030")
    doc.fillColor(v ? "#22543d" : "#742a2a").font("Helvetica-Bold").fontSize(12)
      .text(v ? "VERIFIED: every check against the ledger passed" : `NOT VERIFIED: ${body.verdict.failedChecks.join("; ")}`, doc.x + 10, doc.y + 11)
    doc.fillColor("#111").moveDown(1.2)
    doc.x = 48

    heading("Evidence")
    label("File", body.evidence.name)
    label("Type / size", `${body.evidence.fileType} / ${body.evidence.fileSize} bytes`)
    label("SHA-256", body.evidence.hash)
    label("Uploaded by", body.evidence.uploadedBy)
    label("Uploaded at", body.evidence.timestamp)
    label("Status", String(body.evidence.status).toUpperCase())
    label("Encryption at rest", body.evidence.encryption)

    heading("Ledger anchor")
    label("Ledger", `${body.ledger.mode} · channel ${body.ledger.channel} · chaincode ${body.ledger.chaincode}`)
    if (body.ledgerRecord) {
      label("Creation transaction", body.ledgerRecord.createdTxId)
      label("Last transaction", body.ledgerRecord.lastTxId)
      label("Hash on ledger", body.ledgerRecord.fileHash)
      label("Uploader signature (Ed25519)", body.ledgerRecord.uploaderSignature)
      if (body.ledgerRecord.privateDetailsHash) label("Private case notes hash", body.ledgerRecord.privateDetailsHash)
    } else {
      doc.text("No ledger record found.")
    }

    heading("Integrity checks")
    for (const c of body.checks) {
      doc.font("Helvetica-Bold").fontSize(9).fillColor(c.ok ? "#22543d" : "#c53030").text(`${c.ok ? "PASS" : "FAIL"}  `, { continued: true })
        .fillColor("#111").text(c.name, { continued: true }).font("Helvetica").fillColor("#444").text(`  ${c.detail}`)
      doc.fillColor("#111")
    }

    heading(`Custody timeline (${body.custodyTimeline.length} events)`)
    for (const t of body.custodyTimeline) {
      doc.font("Helvetica-Bold").fontSize(9).text(`${t.timestamp}  ${String(t.action).replace(/_/g, " ")}`, { continued: true })
        .font("Helvetica").text(`  by ${t.performedBy}`)
      doc.font("Courier").fontSize(7).fillColor("#555")
        .text(`block ${t.blockNumber ?? "?"} · tx ${t.txHash} · ${t.ledgerMatch ? "matches ledger" : "NOT FOUND ON LEDGER"}`).fillColor("#111")
    }

    heading("Report seal")
    doc.font("Helvetica").fontSize(9).text(
      "The SHA-256 below is computed over the canonical JSON version of this report (download it with format=json). " +
      "It was written to the ledger in the export transaction, and signed with the gateway's Ed25519 report key (GET /api/report-key)."
    )
    doc.moveDown(0.3)
    label("Report SHA-256", seal.reportHash)
    label("Export transaction", `${seal.exportTx} (block ${seal.exportBlock})`)
    label("Gateway signature", seal.gatewaySignature)

    doc.end()
  })
}
