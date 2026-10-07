// Verbatim copy of federation-port src/contract/types.ts at commit 92d5078 (aeoess/federation-port,
// Apache-2.0). Kept here so the adapter's type-only import resolves from this package exactly as it
// would from federation-port's own adapters/ directory. Not modified.
// Published adapter contract, federation-port/v0. Exploratory, local only.
// Adapters import types from this file and nothing from src/runtime.

export const CONTRACT_VERSION = 'federation-port/v0'

export type Role =
  | 'authority_evidence'
  | 'action_evaluation'
  | 'tool_admission'
  | 'execution'
  | 'payment_verification'
  | 'receipt_verification'

/** Minimal JSON Schema subset understood by the V0 runtime. */
export interface JsonSchema {
  type?: 'object' | 'string' | 'integer' | 'number' | 'boolean' | 'array'
  properties?: Record<string, JsonSchema>
  required?: string[]
  additionalProperties?: boolean
  enum?: unknown[]
  pattern?: string
  minimum?: number
  description?: string
}

export interface ClaimDefinition {
  /** Claim id, unique within this manifest. The runtime always qualifies it by component id. */
  id: string
  /** What an `established` result means, in one sentence. */
  establishes: string
  /** What an `established` result does not mean. */
  limits: string[]
}

export interface ToolDefinition {
  name: string
  description: string
  input_schema: JsonSchema
}

export interface Manifest {
  contract: typeof CONTRACT_VERSION
  /** Namespaced component id, e.g. "example.sim/refund-executor". */
  id: string
  publisher: { name: string; contact?: string }
  maintainer: { name: string; contact?: string }
  artifact: {
    version: string
    /** Module entry, relative to the manifest. Must export `createAdapter`. */
    entry: string
    /** Files covered by `digest`, relative to the manifest. */
    files: string[]
    /** "sha256:" + hex over the files, see spec/CONTRACT.md section 3. */
    digest: string
    /** Declared runtime dependencies. Recorded, not verified by V0. */
    dependencies?: Record<string, string>
  }
  role: Role
  schemas: {
    /** Shape of the native evidence bytes this component accepts in check(). */
    check_evidence?: { media_type: string; description: string }
    /** Shape of the native evidence bytes this component returns. */
    output_evidence: { media_type: string; description: string }
    execute_input?: JsonSchema
  }
  claims: ClaimDefinition[]
  profiles: { id: string; description: string }[]
  /** Execution role only: tool definitions this component dispatches. Pinned with the manifest. */
  tools?: ToolDefinition[]
  /** e.g. "secret:provider_api_key", "side_effect:refund". Must be a subset of the operator grant. */
  privileges_requested: string[]
  /** Origins the component sends data to, e.g. "http://127.0.0.1:*". Must be a subset of the operator grant. */
  data_destinations: string[]
  keys: { id: string; purpose: string; held_by: 'publisher' | 'customer' | 'none'; lifecycle: string }[]
  license: { spdx: string; attribution: string }
  price_terms?: { model: string; note: string }
}

export type ClaimStatus = 'established' | 'not_established' | 'failed' | 'unsupported'
export const CLAIM_STATUSES: readonly ClaimStatus[] = ['established', 'not_established', 'failed', 'unsupported']

export interface ClaimResult {
  claim: string
  status: ClaimStatus
  reason?: string
}

export interface Action {
  tool: string
  args: Record<string, unknown>
}

export interface CheckInput {
  operation_id: string
  workflow: string
  /** Customer-supplied tenant id the operation is bound to, if any. */
  tenant?: string
  approval_id?: string
  /** The exact action the runtime will dispatch if admitted. A copy; mutation has no effect. */
  action: Action
  /** Native evidence bytes addressed to this component only, if the caller supplied any. */
  evidence?: Uint8Array
  /** Evaluation instant, ISO 8601 UTC with milliseconds. */
  now: string
}

export interface CheckOutput {
  /** Native evidence bytes the component relied on, unmodified by the runtime. */
  evidence: Uint8Array
  claims: ClaimResult[]
  /**
   * Last instant at which the established claims may be acted on, exact UTC milliseconds
   * (YYYY-MM-DDTHH:MM:SS.sssZ). Inclusive: admissible while now <= valid_until. The runtime
   * re-checks it against a fresh clock inside the admission write. Any other form is a protocol
   * violation and makes every claim of this component unavailable.
   */
  valid_until?: string
}

export interface ExecuteOp {
  /** One logical operation id. Identical across retries. */
  operation_id: string
  /** Provider idempotency key. Identical across retries. */
  idempotency_key: string
  attempt: number
  action: Action
}

export type ExecuteOutcome = 'provider_confirmed' | 'failed' | 'unknown'

export interface ExecuteOutput {
  outcome: ExecuteOutcome
  /** For `failed`: true when the provider did not perform the side effect and a retry is safe. */
  retriable?: boolean
  provider_ref?: string
  reason?: string
  evidence: Uint8Array
}

export interface Adapter {
  describe(): Manifest
  check?(input: CheckInput): Promise<CheckOutput>
  execute?(op: ExecuteOp): Promise<ExecuteOutput>
}

export interface AdapterContext {
  /** Component configuration from the customer policy (trusted keys, endpoints, pins). */
  config: Record<string, unknown>
  /** Only the secrets whose `secret:<name>` privilege the operator granted. */
  secrets: Readonly<Record<string, string>>
  /** fetch restricted to the granted data destinations. */
  fetch: typeof fetch
}

export type AdapterFactory = (ctx: AdapterContext) => Adapter
