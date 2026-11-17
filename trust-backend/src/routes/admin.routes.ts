import { Router } from "express"
import multer from "multer"
import { reportPublicKeyPem } from "../services/report.service"
import { authMiddleware } from "../middleware/auth.middleware"
import { opaMiddleware } from "../middleware/opa.middleware"
import {
  listDIDs,
  resolveDID,
  verifyDIDSignature,
  listAllUsers,
  authorizeUser,
  getOpaPolicyDashboard,
  simulateOpaPolicy,
  getFirewallStatus,
  resetFirewall,
  getLedgerStatus,
  reconcileNow,
  listRecoveryRequests,
  approveRecovery,
  rejectRecovery,
  legacyImport,
  connectorStatus
} from "../controllers/admin.controller"
import { requestChallenge, verifyChallenge, registerUser, getCurrentUser, requestRecovery } from "../controllers/auth.controller"

const router = Router()

// Authentication: DID challenge-response -> short-lived session JWT
router.post("/auth/challenge", requestChallenge)
router.post("/auth/verify", verifyChallenge)

// Registration (public key only) and profile
router.post("/users/register", registerUser)
router.get("/users/me", authMiddleware, getCurrentUser)

// Lost-key recovery request (public; needs administrator approvals before anything changes)
router.post("/recovery/request", requestRecovery)

// Public DID resolution and signature verification (no signing endpoint: keys never leave the client)
router.get("/did", listDIDs)
router.get("/did/:did", resolveDID)
router.post("/did/verify", verifyDIDSignature)
// Public key that signs courtroom reports
router.get("/report-key", (_req, res) => res.json({ success: true, data: { algorithm: "Ed25519", publicKeyPem: reportPublicKeyPem() } }))

// Identity administration (admin only)
router.get("/admin/users", authMiddleware, opaMiddleware("manage_users"), listAllUsers)
router.patch(
  "/admin/users/:uid/authorize",
  authMiddleware,
  opaMiddleware(req => (req.body?.status === "revoked" ? "revoke_user" : req.body?.status === "approved" ? "approve_user" : "manage_users")),
  authorizeUser
)

// Identity recovery approvals (admin only; quorum of distinct admins enforced by the service)
router.get("/admin/recovery", authMiddleware, opaMiddleware("manage_users"), listRecoveryRequests)
router.post("/admin/recovery/:id/approve", authMiddleware, opaMiddleware("approve_user"), approveRecovery)
router.post("/admin/recovery/:id/reject", authMiddleware, opaMiddleware("manage_users"), rejectRecovery)

// Legacy logbook import and case-management connector (admin only)
const csvUpload = multer({ storage: multer.memoryStorage(), limits: { fileSize: 5 * 1024 * 1024, files: 1 } })
router.post("/admin/legacy-import", authMiddleware, opaMiddleware("import_legacy"), csvUpload.single("file"), legacyImport)
router.get("/admin/connector", authMiddleware, opaMiddleware("manage_users"), connectorStatus)

// Oversight (admin, auditor)
router.get("/admin/opa", authMiddleware, opaMiddleware("view_policy"), getOpaPolicyDashboard)
router.post("/admin/opa/evaluate", authMiddleware, opaMiddleware("view_policy"), simulateOpaPolicy)
router.get("/admin/ledger", authMiddleware, opaMiddleware("audit_ledger"), getLedgerStatus)
router.post("/admin/reconcile", authMiddleware, opaMiddleware("audit_ledger"), reconcileNow)

// Firewall (admin only)
router.get("/admin/firewall", authMiddleware, opaMiddleware("manage_firewall"), getFirewallStatus)
router.post("/admin/firewall/reset", authMiddleware, opaMiddleware("manage_firewall"), resetFirewall)

export default router
