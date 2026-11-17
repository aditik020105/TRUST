import cron from "node-cron"
import axios from "axios"

const SELF_URL = process.env.SELF_URL ?? "https://your-backend.onrender.com"

export const startHealthCheckJob = () => {
  cron.schedule("*/12 * * * *", async () => {
    try {
      await axios.get(`${SELF_URL}/ping`)
      console.log("🔁 Health check ping sent:", new Date().toISOString())
    } catch (err: any) {
      console.error("❌ Health check failed:", err.message)
    }
  })

  console.log("⏰ Health check cron job started (every 12 minutes)")
}