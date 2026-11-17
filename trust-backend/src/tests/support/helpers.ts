import { userService, UserRole, UserStatus, UserRecord } from "../../services/user.service"
import { generateEd25519KeyPair, signWithPrivateKeyPem, signingPayloads } from "../../services/did.service"
import { issueSessionToken } from "../../services/auth.service"

export interface TestActor {
  user: UserRecord
  privateKeyPem: string
  token: string
  auth: string
  sign: (payload: string) => string
}

let counter = 0

/** Registers a user from a fresh keypair (the private key stays in the test, like in the browser). */
export async function createActor(role: UserRole, status: UserStatus = "approved"): Promise<TestActor> {
  const keys = generateEd25519KeyPair()
  const user = await userService.registerUser({
    email: `${role}.${status}.${++counter}@trust.test`,
    displayName: `${role} ${counter}`,
    publicKey: keys.publicKeyHex,
    authProvider: "key",
    forceRole: role,
    forceStatus: status
  })
  const { token } = issueSessionToken(user)
  return {
    user,
    privateKeyPem: keys.privateKeyPem,
    token,
    auth: `Bearer ${token}`,
    sign: (payload: string) => signWithPrivateKeyPem(keys.privateKeyPem, payload)
  }
}

export { signingPayloads }
