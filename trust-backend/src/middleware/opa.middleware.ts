import { Response, NextFunction } from "express"
import { AuthRequest } from "./auth.middleware"
import { opaService, OpaInput } from "../services/opa.service"

/**
 * Open Policy Agent (OPA) enforcement middleware.
 * Evaluates incoming request attributes (user DID, role, MSP, approval status, action, and parameters)
 * against `policies/trust_authz.rego`.
 * If denied, returns HTTP 403 Forbidden with explicit Server Rejection details.
 */
export function opaMiddleware(actionOrResolver: string | ((req: AuthRequest) => string)) {
  return async (req: AuthRequest, res: Response, next: NextFunction) => {
    const action = typeof actionOrResolver === "function" ? actionOrResolver(req) : actionOrResolver
    const user = req.user
    if (!user) {
      res.status(401).json({ success: false, code: "AUTH_REQUIRED", error: "Authentication required" })
      return
    }

    const input: OpaInput = {
      method: req.method,
      path: req.originalUrl || req.path,
      action,
      resource: req.baseUrl + req.path,
      user: {
        uid: user.uid,
        email: user.email,
        did: user.did,
        role: user.role,
        mspId: user.mspId,
        status: user.status
      },
      parameters: {
        ...(req.body || {}),
        ...(req.query || {}),
        ...(req.params || {})
      }
    }

    const decision = await opaService.evaluate(input)

    // Attach OPA headers so client & dev tools can inspect policy decision on every response
    res.setHeader("X-OPA-Decision", decision.allow ? "ALLOW" : "DENY")
    res.setHeader("X-OPA-Rule", decision.rule)

    if (!decision.allow) {
      res.status(403).json({
        success: false,
        error: decision.reason,
        code: "OPA_POLICY_REJECTED",
        opaDecision: {
          id: decision.id,
          allow: false,
          rule: decision.rule,
          reason: decision.reason,
          timestamp: decision.timestamp,
          evaluatedContext: {
            did: input.user.did,
            role: input.user.role,
            mspId: input.user.mspId,
            userStatus: input.user.status,
            action: input.action,
            resource: input.path,
            parameters: input.parameters
          }
        }
      })
      return
    }

    next()
  }
}

