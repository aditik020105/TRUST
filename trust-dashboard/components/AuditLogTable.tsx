import { AuditEntry } from "@/types"
import styles from "./AuditLogTable.module.css"

export default function AuditLogTable({ entries }: { entries: AuditEntry[] }) {
  return (
    <div className={styles.wrapper}>
      <table className={styles.table}>
        <thead>
          <tr>
            <th>Action</th>
            <th>Evidence ID</th>
            <th>Case ID</th>
            <th>Performed By</th>
            <th>Timestamp</th>
            <th>Block</th>
            <th>TX Hash</th>
          </tr>
        </thead>
        <tbody>
          {(entries || []).map(entry => {
            const actionStr = String(entry.action || "uploaded")
            return (
              <tr key={entry.id}>
                <td className={styles.action}>
                  <span className={`${styles.actionBadge} ${styles[actionStr] ?? styles.uploaded}`}>
                    {actionStr.replace(/_/g, " ")}
                  </span>
                </td>
                <td>{entry.evidenceId ?? "—"}</td>
                <td className={styles.caseId}>{entry.caseId ?? "—"}</td>
                <td>{entry.performedBy ?? "—"}</td>
                <td>{entry.timestamp ? new Date(entry.timestamp).toLocaleString() : "—"}</td>
                <td>{entry.blockNumber ?? "—"}</td>
                <td className={styles.txHash} title={entry.txHash}>{entry.txHash ? `${entry.txHash.slice(0, 16)}…` : "—"}</td>
              </tr>
            )
          })}
        </tbody>
      </table>
    </div>
  )
}