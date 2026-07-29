/**
 * Chain-agnostic core contracts.
 *
 * Naming conventions (spec Appendix E): the core never uses chain-specific
 * vocabulary — `accountIdentifier` (never `actor`), `chain`/`network`/`chainId`
 * everywhere (INV-013), `signedTransaction` (never `packedXprTransaction`).
 */

export interface ChainContext {
  chain: string;
  network: string;
  chainId: string;
}

export interface AccountIdentity {
  accountIdentifier: string;
  permission?: string;
}

export interface NetworkDescriptor {
  network: string;
  chainId: string;
  endpoints: string[];
}

/**
 * A single decoded action in chain-agnostic form, produced by a ChainAdapter
 * from the raw unserialized JSON input (INV-014). This is the only
 * representation the policy engine ever evaluates.
 */
export interface DecodedAction {
  contract: string;
  action: string;
  authorization: Required<AccountIdentity>[];
  data: Record<string, unknown>;
}

export interface DecodedTransaction {
  context: ChainContext;
  actions: DecodedAction[];
}

export type ExportPolicy = "non-exportable" | "encrypted-backup-only";

/** Machine-readable refusal categories. Safe to return to the agent (§12.2). */
export type DenyCode =
  | "SCHEMA_INVALID"
  | "CHAIN_MISMATCH"
  | "EMPTY_TRANSACTION"
  | "MULTI_AUTHORIZATION"
  | "AUTHORIZATION_MISMATCH"
  | "RULE_DENY"
  | "DEFAULT_DENY"
  | "LIMIT_EXCEEDED"
  | "AMBIGUOUS_VALUE"
  | "POLICY_UNAVAILABLE"
  | "AGENT_DISABLED"
  | "INTERNAL_ERROR";

/**
 * The single structured output of the policy engine. `safeReason` is a
 * category, never an exact threshold, list entry or rule internals (§11.6).
 */
export type Decision =
  | {
      effect: "allow";
      /** ids of the allow rules that matched, one per action, in order */
      ruleIds: string[];
      policyVersion: number;
    }
  | {
      effect: "deny";
      code: DenyCode;
      safeReason: string;
      policyVersion?: number;
    };

/** Opaque reference to a stored key. Never contains secret material. */
export interface KeyHandle {
  keyId: string;
  publicKey: string;
  exportPolicy: ExportPolicy;
  chain: ChainContext;
  agent: string;
  permission: string;
}

/**
 * Future-facing seam for native/HSM backends (spec §6.3). The MVP
 * encrypted-file backend implements scoped secret access instead of raw
 * export: the secret only ever exists inside the daemon process.
 */
export interface KeyBackend {
  readonly kind: "encrypted-file" | "os-keystore" | "pkcs11" | "hardware";
}

/**
 * ChainAdapter (spec §5.4). V1 ships a single implementation: XprChainAdapter.
 * The core engine never imports anything chain-specific.
 */
export interface ChainAdapter {
  readonly chain: string;
  listNetworks(): Promise<NetworkDescriptor[]>;
  resolveChainId(network: string): Promise<string>;
  /**
   * Validate and normalize raw unserialized JSON input (INV-014) into the
   * chain-agnostic decoded form. Throws on any unknown field, packed payload,
   * hex data or structural violation — never a partial decode (INV-003).
   */
  decodeTransaction(input: unknown, context: ChainContext): Promise<DecodedTransaction>;
}
