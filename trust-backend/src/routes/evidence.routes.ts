import { Router } from "express"
import multer from "multer"
import { authMiddleware } from "../middleware/auth.middleware"
import { opaMiddleware } from "../middleware/opa.middleware"
import {
  getAllEvidence,
  getEvidenceById,
  uploadEvidence,
  updateEvidenceStatus,
  viewEvidenceFile,
  downloadEvidenceFile,
  verifyEvidence,
  getPrivateDetails,
  exportCourtReport
} from "../controllers/evidence.controller"

const router = Router()
const maxMb = Number(process.env.MAX_UPLOAD_MB || 50)
const upload = multer({ storage: multer.memoryStorage(), limits: { fileSize: maxMb * 1024 * 1024, files: 1 } })

router.get("/", authMiddleware, opaMiddleware("list_evidence"), getAllEvidence)
router.get("/:id/view", authMiddleware, opaMiddleware("view_evidence"), viewEvidenceFile)
router.get("/:id/download", authMiddleware, opaMiddleware("download_evidence"), downloadEvidenceFile)
router.get("/:id/verify", authMiddleware, opaMiddleware("verify_integrity"), verifyEvidence)
router.get("/:id/report", authMiddleware, opaMiddleware("export_report"), exportCourtReport)
router.get("/:id/private", authMiddleware, opaMiddleware("read_private_details"), getPrivateDetails)
router.get("/:id", authMiddleware, opaMiddleware("inspect_evidence"), getEvidenceById)
// Policy is checked before the multipart body is read, so a denied caller never streams a file in.
router.post("/upload", authMiddleware, opaMiddleware("upload_evidence"), upload.single("file"), uploadEvidence)
router.patch("/:id/status", authMiddleware, opaMiddleware("update_evidence_status"), updateEvidenceStatus)

export default router
