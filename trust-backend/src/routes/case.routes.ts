import { Router } from "express"
import { authMiddleware } from "../middleware/auth.middleware"
import { opaMiddleware } from "../middleware/opa.middleware"
import { listCases, grantAccess, revokeAccess } from "../controllers/case.controller"
import { exportCaseCustody } from "../controllers/evidence.controller"

const router = Router()

router.get("/", authMiddleware, opaMiddleware("list_evidence"), listCases)
router.get("/:caseId/custody", authMiddleware, opaMiddleware("read_audit_log"), exportCaseCustody)
// Role check here; the service additionally requires the caller to own the case (or be admin).
router.post("/:caseId/access", authMiddleware, opaMiddleware("delegate_case_access"), grantAccess)
router.post("/:caseId/access/:grantId/revoke", authMiddleware, opaMiddleware("delegate_case_access"), revokeAccess)

export default router
