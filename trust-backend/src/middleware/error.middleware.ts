import { Request, Response, NextFunction } from "express"

export function errorMiddleware(err: any, _req: Request, res: Response, _next: NextFunction) {
  if (err?.name === "MulterError") {
    const status = err.code === "LIMIT_FILE_SIZE" ? 413 : 400
    return res.status(status).json({ success: false, error: err.message })
  }
  const status = err?.status || err?.statusCode || 500
  if (status >= 500) console.error(`[ERROR] ${err?.stack || err?.message || err}`)
  res.status(status).json({
    success: false,
    error: status >= 500 && process.env.NODE_ENV === "production" ? "Internal server error" : err?.message || "Error"
  })
}
