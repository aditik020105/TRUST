import fs from "fs"
import os from "os"
import path from "path"

// Runs before each test file is loaded: every file gets its own empty DB, storage and ledger.
const dir = fs.mkdtempSync(path.join(os.tmpdir(), "trust-test-"))
process.env.NODE_ENV = "test"
process.env.DATA_DIR = path.join(dir, "data")
process.env.STORAGE_DIR = path.join(dir, "storage")
process.env.JWT_SECRET = "test-secret-" + Math.random().toString(36).slice(2)
process.env.TRUST_PROXY = "true"
process.env.EVIDENCE_ENCRYPTION_KEY = "11".repeat(32)
process.env.RECONCILE_CRON = "off"
// Existing suites exercise roles across shared cases; case-access.test.ts switches to "restricted".
process.env.CASE_ACCESS_MODE = "open"
process.env.SUPABASE_URL = ""
process.env.SUPABASE_SERVICE_KEY = ""
process.env.FIREBASE_PROJECT_ID = ""
process.env.ADMIN_EMAILS = ""
// TEST_LEDGER_MODE=fabric runs the suites against a live Fabric network (fabric/native/start-network.sh);
// the FABRIC_* variables must then be set in the environment.
if (process.env.TEST_LEDGER_MODE === "fabric") process.env.LEDGER_MODE = "fabric"
else process.env.LEDGER_MODE = ""
process.env.OPA_URL = ""
