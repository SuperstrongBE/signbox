/**
 * The XPR ChainModule — assembles the existing XPR implementations behind the
 * chain registry (issue #44 phase A). Pure wiring: every factory returns the
 * same class, with the same options, that the assembly points constructed
 * directly before the registry existed. No behavior change.
 */

import { JsonRpc } from "@proton/js";
import type { ChainContext, DecodedTransaction } from "../../core/types.js";
import { SignBoxError } from "../../core/errors.js";
import { XprTransactionSigner, pinChainId } from "./adapter.js";
import { decodeXprTransaction } from "./decode.js";
import { generateK1KeyPair } from "./keygen.js";
import { XPR_CHAIN, XPR_NETWORKS } from "./networks.js";
import { XprTransactionBroadcaster } from "./broadcaster.js";
import { XprChainReadRelay } from "./relay.js";
import { XprPolicyReader } from "./policyReader.js";
import { XprOnboardingBackend } from "./onboarding.js";
import { xprDialect } from "./dialect.js";
import type { ChainModule, ChainWiring } from "../registry.js";
import type { KeystoreBackend } from "../../keystore/backend.js";

const ONBOARDING_SCHEMES = ["esr", "proton", "proton-dev"] as const;
type OnboardingScheme = (typeof ONBOARDING_SCHEMES)[number];

export const xprModule: ChainModule = {
  chain: XPR_CHAIN,
  networks: XPR_NETWORKS,

  // Antelope chain ids are 64 lowercase hex; the policy registry is hosted by
  // an Antelope account (a-z, 1-5, dots, ≤ 12 chars).
  chainIdPattern: /^[0-9a-f]{64}$/,
  registryLocatorPattern: /^[a-z1-5.]{1,12}$/,

  dialect: xprDialect,

  decode(input: unknown, context: ChainContext): DecodedTransaction {
    return decodeXprTransaction(input, context);
  },

  generateKeyPair: generateK1KeyPair,

  createSigner(wiring: ChainWiring, keystore: KeystoreBackend) {
    return new XprTransactionSigner({ ...wiring, keystore });
  },

  createBroadcaster(wiring: ChainWiring) {
    return new XprTransactionBroadcaster(wiring);
  },

  createRelay(wiring: ChainWiring) {
    return new XprChainReadRelay(wiring);
  },

  createPolicyReader(wiring: ChainWiring, registryLocator: string) {
    return new XprPolicyReader({ ...wiring, contractAccount: registryLocator });
  },

  createOnboardingBackend(wiring: ChainWiring, registryLocator: string, options = {}) {
    const scheme = options["scheme"];
    if (scheme !== undefined && !ONBOARDING_SCHEMES.includes(scheme as OnboardingScheme)) {
      throw new SignBoxError(`scheme must be one of: ${ONBOARDING_SCHEMES.join(", ")}`);
    }
    const companionBaseUrl = options["companionBaseUrl"];
    return new XprOnboardingBackend({
      ...wiring,
      signboxContract: registryLocator,
      ...(scheme !== undefined ? { scheme: scheme as OnboardingScheme } : {}),
      ...(companionBaseUrl !== undefined ? { companionBaseUrl } : {}),
    });
  },

  async broadcastSigned(wiring: ChainWiring, signed: unknown): Promise<unknown> {
    const payload = signed as { signatures?: string[]; packedTransaction?: string };
    if (!Array.isArray(payload?.signatures) || typeof payload?.packedTransaction !== "string") {
      throw new SignBoxError(
        "signed transaction must contain { signatures, packedTransaction } as produced by sign",
      );
    }
    const rpc = new JsonRpc(wiring.endpoints);
    pinChainId(rpc, wiring.chainId);
    await rpc.get_info(); // validates the pinned chain id before any broadcast (INV-009)
    return rpc.push_transaction({
      signatures: payload.signatures,
      serializedTransaction: Uint8Array.from(Buffer.from(payload.packedTransaction, "hex")),
    });
  },

  async checkEndpoint(wiring: ChainWiring): Promise<{ headTimeMs?: number }> {
    const rpc = new JsonRpc(wiring.endpoints);
    pinChainId(rpc, wiring.chainId);
    const info = (await rpc.get_info()) as { head_block_time?: string };
    return info.head_block_time !== undefined
      ? { headTimeMs: Date.parse(`${info.head_block_time}Z`) }
      : {};
  },

  async checkPolicyRegistry(wiring: ChainWiring, registryLocator: string): Promise<void> {
    const rpc = new JsonRpc(wiring.endpoints);
    pinChainId(rpc, wiring.chainId);
    await rpc.get_abi(registryLocator); // throws when the contract isn't deployed
  },
};
