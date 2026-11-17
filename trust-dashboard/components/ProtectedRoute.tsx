"use client"

import React, { useEffect } from "react"
import Link from "next/link"
import { useRouter } from "next/navigation"
import { useAuth } from "@/context/AuthContext"
import { ShieldCheck, Loader2, Lock } from "lucide-react"

export default function ProtectedRoute({
  children,
  roles
}: {
  children: React.ReactNode
  /** If set, only approved users with one of these roles see the page (the API enforces the same rule). */
  roles?: string[]
}) {
  const { user, loading } = useAuth()
  const router = useRouter()

  useEffect(() => {
    if (!loading && !user) router.push("/login")
  }, [user, loading, router])

  if (loading) {
    return (
      <div style={{ minHeight: "calc(100vh - 80px)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "1rem", color: "#94a3b8" }}>
        <Loader2 className="animate-spin" size={32} style={{ color: "#ef4444" }} />
        <div style={{ display: "flex", alignItems: "center", gap: "0.5rem", fontSize: "0.9rem" }}>
          <ShieldCheck size={18} />
          <span>Verifying TRUST session...</span>
        </div>
      </div>
    )
  }

  if (!user) return null

  if (roles && (!roles.includes(user.role) || user.status !== "approved")) {
    return (
      <div style={{ minHeight: "calc(100vh - 80px)", display: "flex", flexDirection: "column", alignItems: "center", justifyContent: "center", gap: "0.75rem", color: "#94a3b8", textAlign: "center", padding: "1rem" }}>
        <Lock size={28} style={{ color: "#ef4444" }} />
        <div style={{ fontWeight: 700, color: "#e2e8f0" }}>Not available for your account</div>
        <div style={{ fontSize: "0.85rem", maxWidth: 420 }}>
          This page needs an approved {roles.join(" or ")} account. You are signed in as {user.role} ({user.status}).
        </div>
        <Link href="/dashboard" style={{ color: "#f87171", textDecoration: "underline", fontSize: "0.85rem" }}>Back to dashboard</Link>
      </div>
    )
  }

  return <>{children}</>
}
