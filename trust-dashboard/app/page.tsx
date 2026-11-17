import Link from "next/link"
import { ShieldCheck, FileSearch, Lock, ArrowRight, Users, Database, Eye } from "lucide-react"
import styles from "./page.module.css"

export default function Home() {
  return (
    <div className={styles.page}>

      {/* Hero */}
      <section className={styles.hero}>
        <div className={styles.heroInner}>
          <div className={styles.heroBadge}>
            <Lock size={12} />
            <span>Blockchain-Secured Evidence Management</span>
          </div>
          <h1 className={styles.heroTitle}>
            Tamper-Proof Chain of<br />Custody for Digital Evidence
          </h1>
          <p className={styles.heroSub}>
            TRUST uses decentralized identity, smart contracts, and cryptographic audit trails
            to ensure every piece of evidence is verifiable, traceable, and court-admissible.
          </p>
          <div className={styles.heroActions}>
            <Link href="/dashboard" className={styles.btnPrimary}>
              Go to Dashboard <ArrowRight size={16} />
            </Link>
            <Link href="/audit-log" className={styles.btnSecondary}>
              View Audit Log
            </Link>
          </div>
        </div>
      </section>

      {/* Features */}
      <section className={styles.features}>
        <h2 className={styles.sectionTitle}>Why TRUST?</h2>
        <p className={styles.sectionSub}>
          Built to fix the gaps in traditional forensic evidence management
        </p>
        <div className={styles.featureGrid}>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <ShieldCheck size={22} />
            </div>
            <h3>Immutable Audit Trail</h3>
            <p>Every upload, view, download and status change is committed to the ledger before it takes effect, and tied to the DID that did it.</p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <Users size={22} />
            </div>
            <h3>DID-Based Access Control</h3>
            <p>Each officer signs in by signing a one-time challenge with an Ed25519 key that never leaves their browser. A policy engine checks every request.</p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <Lock size={22} />
            </div>
            <h3>Expiring, Revocable Sessions</h3>
            <p>Session tokens expire automatically, and approval status is re-checked on every request, so a revocation takes effect at once.</p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <FileSearch size={22} />
            </div>
            <h3>Cryptographic Verification</h3>
            <p>Each file&apos;s SHA-256 hash and the uploader&apos;s signature are anchored on the ledger. Anyone can recompute and compare.</p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <Database size={22} />
            </div>
            <h3>Off-Chain Storage</h3>
            <p>Files are encrypted with AES-256-GCM and kept off-chain; only hashes and custody events go on the ledger.</p>
          </div>
          <div className={styles.featureCard}>
            <div className={styles.featureIcon}>
              <Eye size={22} />
            </div>
            <h3>Full Transparency</h3>
            <p>Investigators, analysts, and judiciary can verify the complete custody history of any evidence item at any time.</p>
          </div>
        </div>
      </section>

      {/* CTA */}
      <section className={styles.cta}>
        <h2>Ready to manage evidence the right way?</h2>
        <p>Access the dashboard to view, upload, and track all evidence in your cases.</p>
        <Link href="/dashboard" className={styles.btnPrimary}>
          Open Dashboard <ArrowRight size={16} />
        </Link>
      </section>

    </div>
  )
}