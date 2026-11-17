import { initializeApp, getApps, getApp, FirebaseApp } from "firebase/app"
import { getAuth, GoogleAuthProvider, Auth } from "firebase/auth"

const rawApiKey = process.env.NEXT_PUBLIC_FIREBASE_API_KEY

const isConfigured =
  Boolean(rawApiKey) &&
  !rawApiKey!.includes("your-firebase-api-key") &&
  !rawApiKey!.includes("DummyKey") &&
  !rawApiKey!.includes("placeholder")

const firebaseConfig = {
  apiKey: rawApiKey || "AIzaSyDummyKeyForBuildTimeInit1234567890",
  authDomain: process.env.NEXT_PUBLIC_FIREBASE_AUTH_DOMAIN || "trust-custody.firebaseapp.com",
  projectId: process.env.NEXT_PUBLIC_FIREBASE_PROJECT_ID || "trust-custody",
  storageBucket: process.env.NEXT_PUBLIC_FIREBASE_STORAGE_BUCKET || "trust-custody.firebasestorage.app",
  messagingSenderId: process.env.NEXT_PUBLIC_FIREBASE_MESSAGING_SENDER_ID || "47712061065",
  appId: process.env.NEXT_PUBLIC_FIREBASE_APP_ID || "1:477120610657:web:ba876051f4609578780520"
}

let app: FirebaseApp | null = null
let auth: Auth | null = null
const googleProvider = new GoogleAuthProvider()

if (isConfigured) {
  try {
    app = getApps().length > 0 ? getApp() : initializeApp(firebaseConfig)
    auth = getAuth(app)
  } catch {
    // Fallback when Firebase API key is not configured locally
    app = null
    auth = null
  }
}

export { app, auth, googleProvider }
