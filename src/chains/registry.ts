/**
 * Chain registry (spec §5.4, issue #44 phase A) — the ONE place a chain's
 * implementations are selected from.
 *
 * A ChainModule bundles the per-chain factories behind the core's existing
 * chain-agnostic seams (decode, TransactionSigner, TransactionBroadcaster,
 * ChainReadRelay, PolicyReader, OnboardingBackend, keygen, networks). The
 * daemon runner, the CLI and the MCP server resolve implementations through
 * `getChain(name)` and never import `Xpr*` classes directly.
 *
 * Registration is STATIC — modules are imported and registered at build time
 * (see ./index.ts). No dynamic loading: the audit surface stays closed, and
 * adding a chain is one `src/chains/<chain>/` directory plus one
 * `registerChain(...)` call.
 *
 * Deliberately NOT hidden behind the bundle ("no abstraction that hides the
 * real guarantees of each chain", spec Phase 4): per-chain capabilities are
 * explicit, and the `options` records surface chain-specific knobs (e.g. the
 * XPR onboarding `scheme`) instead of pretending uniformity.
 */

import type {
  ChainContext,
  DecodedTransaction,
  NetworkDescriptor,
  TransactionSigner,
  KeyHandle,
} from "../core/types.js";
import type { TransactionBroadcaster } from "../daemon/broadcaster.js";
import type { ChainReadRelay } from "../daemon/chainRelay.js";
import type { PolicyReader } from "../daemon/chainPolicyReader.js";
import type { OnboardingBackend } from "../onboarding/flow.js";

/** Endpoint + pinned chain id — what every network-touching factory needs. */
export interface ChainWiring {
  endpoints: string[];
  chainId: string;
}

/**
 * The seam the signer pulls key material through. WIF-shaped today — this is
 * the boundary issue #46 replaces with a no-export `signDigest` backend.
 */
export type PrivateKeyProvider = (key: KeyHandle) => Promise<string>;

export interface ChainKeyPair {
  wif: string;
  publicKey: string;
}

export interface ChainModule {
  /** Chain identifier, e.g. "XPR" — the value of `config.chain` (INV-013). */
  readonly chain: string;

  /** Pinned network table: network name → { chainId, endpoints }. */
  readonly networks: Record<string, NetworkDescriptor>;

  /** Shape of this chain's chain ids (XPR: 64 lowercase hex; others differ). */
  readonly chainIdPattern: RegExp;

  /**
   * Shape of this chain's policy-registry locator — the `signboxContract`
   * config value (XPR: an Antelope account name; an object id / contract
   * address for future chains).
   */
  readonly registryLocatorPattern: RegExp;

  /** Normalize + validate a raw unserialized JSON transaction (INV-014). */
  decode(input: unknown, context: ChainContext): DecodedTransaction;

  /** Generate a fresh agent key pair (used by onboarding / `key generate`). */
  generateKeyPair(): Promise<ChainKeyPair>;

  createSigner(wiring: ChainWiring, keys: PrivateKeyProvider): TransactionSigner;
  createBroadcaster(wiring: ChainWiring): TransactionBroadcaster;
  createRelay(wiring: ChainWiring): ChainReadRelay;

  /**
   * Reader for the chain's policy registry. `registryLocator` addresses the
   * registry in the chain's own vocabulary (Antelope account name today; an
   * object id / contract address for future chains).
   */
  createPolicyReader(wiring: ChainWiring, registryLocator: string): PolicyReader;

  /**
   * Onboarding backend. `options` carries chain-specific knobs the generic
   * assembly cannot know about (XPR: `scheme`, `companionBaseUrl`).
   */
  createOnboardingBackend(
    wiring: ChainWiring,
    registryLocator: string,
    options?: Record<string, string>,
  ): OnboardingBackend;

  /**
   * Broadcast an already-signed transaction (chain-id pinned, INV-009). The
   * payload shape is the chain's own signed output — validated here, not by
   * the caller.
   */
  broadcastSigned(wiring: ChainWiring, signed: unknown): Promise<unknown>;

  /**
   * Diagnostics (doctor): verify an endpoint serves the pinned chain id and
   * report its head time (for clock-skew checks). Throws on mismatch/failure.
   */
  checkEndpoint(wiring: ChainWiring): Promise<{ headTimeMs?: number }>;

  /** Diagnostics (doctor): verify the policy registry is deployed. Throws if not. */
  checkPolicyRegistry(wiring: ChainWiring, registryLocator: string): Promise<void>;
}

const modules = new Map<string, ChainModule>();

export function registerChain(module: ChainModule): void {
  if (modules.has(module.chain)) {
    throw new Error(`chain already registered: ${module.chain}`);
  }
  modules.set(module.chain, module);
}

/** Resolve a registered chain, or throw with the registered alternatives. */
export function getChain(name: string): ChainModule {
  const module = modules.get(name);
  if (module === undefined) {
    throw new Error(
      `unsupported chain "${name}" — registered: ${[...modules.keys()].join(", ") || "(none)"}`,
    );
  }
  return module;
}

export function registeredChains(): string[] {
  return [...modules.keys()];
}
