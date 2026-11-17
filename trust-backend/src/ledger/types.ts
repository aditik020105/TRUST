import type { SUBMIT_FUNCTIONS, EVALUATE_FUNCTIONS } from "./evidence-logic"

export type SubmitFn = keyof typeof SUBMIT_FUNCTIONS
export type EvaluateFn = keyof typeof EVALUATE_FUNCTIONS

export interface LedgerTxResult<T = any> {
  txId: string
  blockNumber: number
  result: T
}

export interface ChainVerification {
  ok: boolean
  height: number
  checkedBlocks: number
  firstBadBlock?: number
  reason?: string
}

export interface LedgerInfo {
  mode: "local" | "fabric"
  channel: string
  chaincode: string
  mspId: string
  height?: number
  endpoint?: string
}

/**
 * A ledger accepts the transactions defined in evidence-logic.ts.
 * submit() commits a transaction and resolves only after it is committed;
 * it rejects if the contract rules refuse it or the network is unreachable.
 */
export interface LedgerCallOptions {
  /** Application MSP of the acting user (PoliceOrgMSP, ...). Multi-org Fabric submits as that org. */
  mspId?: string
  /** Transient data (never stored in blocks), e.g. { private: <JSON bytes> } */
  transient?: Record<string, Uint8Array>
}

export interface Ledger {
  submit<T = any>(fn: SubmitFn, args: string[], opts?: LedgerCallOptions): Promise<LedgerTxResult<T>>
  evaluate<T = any>(fn: EvaluateFn, args: string[], opts?: LedgerCallOptions): Promise<T>
  info(): Promise<LedgerInfo>
  /** Recomputes the hash chain. Only the local ledger can do this; Fabric peers validate their own blocks. */
  verifyChain?(): Promise<ChainVerification>
  close?(): Promise<void>
}
