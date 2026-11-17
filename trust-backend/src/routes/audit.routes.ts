import { Router } from "express"
import { getAuditLog } from "../controllers/audit.controller"
import { authMiddleware } from "../middleware/auth.middleware"
import { opaMiddleware } from "../middleware/opa.middleware"

const router = Router()

router.get("/", authMiddleware, opaMiddleware("read_audit_log"), getAuditLog)

export default router