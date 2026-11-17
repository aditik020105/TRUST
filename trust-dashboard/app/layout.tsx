import type { Metadata } from "next"
import Navbar from "@/components/Navbar"
import { AuthProvider } from "@/context/AuthContext"
// @ts-ignore: allow side-effect CSS import without type declarations
import "./globals.css"

export const metadata: Metadata = {
  title: "TRUST - Chain of Custody System",
  description: "Trusted Record Access and Audit Trails using Encrypted Ledger and Ownership Control",
}

export default function RootLayout({ children }: { children: React.ReactNode }) {
  return (
    <html lang="en">
      <body>
        <AuthProvider>
          <Navbar />
          <main>
            {children}
          </main>
        </AuthProvider>
      </body>
    </html>
  )
}