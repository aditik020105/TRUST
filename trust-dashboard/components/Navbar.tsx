"use client"

import React from "react"
import Link from "next/link"
import { usePathname } from "next/navigation"
import { useAuth } from "@/context/AuthContext"
import { ShieldCheck, Home, LogIn, LogOut, Clock } from "lucide-react"
import styles from "./Navbar.module.css"

export default function Navbar() {
  const pathname = usePathname()
  const { user, role, did, mspId, status, logout, sessionExpiresAt } = useAuth()

  // Links are shown only to roles the policy would allow; the backend still enforces OPA on every call.
  const approved = status === "approved"
  const links = user
    ? [
        { href: "/dashboard", label: "Dashboard", show: true },
        { href: "/evidence/upload", label: "Upload Evidence", show: approved && ["investigator", "analyst", "admin"].includes(role) },
        { href: "/cases", label: "Cases", show: approved },
        { href: "/audit-log", label: "Audit Log", show: approved },
        { href: "/admin", label: role === "auditor" ? "Oversight" : "Admin & OPA", show: approved && ["admin", "auditor"].includes(role) }
      ].filter(l => l.show)
    : []

  const handleLogout = async () => {
    try {
      await logout()
    } catch (err) {
      console.error("Failed to log out:", err)
    }
  }

  const safeStatus = status || "pending"
  const safeRole = role || "—"
  const safeMsp = mspId || "—"
  const safeDid = did || "—"
  const expiresAt = sessionExpiresAt ? new Date(sessionExpiresAt).toLocaleTimeString([], { hour: "2-digit", minute: "2-digit" }) : null

  return (
    <nav className={styles.navbar}>
      <div className={styles.brand}>
        <div className={styles.brandRow}>
          <Link href="/" className={styles.homeIcon} title="Home">
            <Home size={16} strokeWidth={1.6} />
          </Link>
          <span className={styles.logo}>TRUST</span>
        </div>
        <span className={styles.tagline}>Chain of Custody System</span>
      </div>

      <div className={styles.links}>
        {links.map(link => (
          <Link
            key={link.href}
            href={link.href}
            className={`${styles.link} ${pathname === link.href ? styles.active : ""}`}
          >
            {link.label}
          </Link>
        ))}
      </div>

      <div className={styles.authSection}>
        {user ? (
          <>
            <div className={styles.userBadge} title={`W3C DID: ${safeDid} | MSP: ${safeMsp} | Status: ${safeStatus}`}>
              <div
                className={styles.dot}
                style={{
                  backgroundColor:
                    safeStatus === "approved" ? "#10b981" : safeStatus === "pending" ? "#f59e0b" : "#ef4444"
                }}
              />
              <ShieldCheck size={14} style={{ color: "#ef4444" }} />
              <div className={styles.userInfo}>
                <span className={styles.userEmail}>{user.displayName || user.email || safeDid}</span>
                <span className={styles.userRole}>
                  {safeRole} • {String(safeStatus).toUpperCase()}
                </span>
              </div>
            </div>

            <span className={styles.mspBadge} title={`Hyperledger Fabric MSP: ${safeMsp} | W3C DID: ${safeDid}`}>
              {safeMsp}
            </span>

            {expiresAt && (
              <span className={styles.mspBadge} title="Session token expiry; you will be signed out automatically">
                <Clock size={11} style={{ marginRight: 4, verticalAlign: "-1px" }} />
                until {expiresAt}
              </span>
            )}

            <button onClick={handleLogout} className={styles.logoutBtn} title="Sign Out">
              <LogOut size={14} />
              <span>Sign Out</span>
            </button>
          </>
        ) : (
          <Link href="/login" className={styles.loginBtn}>
            <LogIn size={14} />
            <span>Sign In</span>
          </Link>
        )}
      </div>
    </nav>
  )
}