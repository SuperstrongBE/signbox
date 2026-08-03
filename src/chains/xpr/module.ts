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
import { XprTransactionBroadcaster } from "../../daemon/broadcaster.js";
import { XprChainReadRelay } from "../../daemon/chainRelay.js";
import { ChainPolicyReader } from "../../daemon/chainPolicyReader.js";
import { XprOnboardingBackend } from "../../onboarding/xprBackend.js";
import type { ChainModule, ChainWiring, PrivateKeyProvider } from "../registry.js";

const ONBOARDING_SCHEMES = ["esr", "proton", "proton-dev"] as const;
type OnboardingScheme = (typeof ONBOARDING_SCHEMES)[number];

export const xprModule: ChainModule = {
  chain: XPR_CHAIN,
  networks: XPR_NETWORKS,

  decode(input: unknown, context: ChainContext): DecodedTransaction {
    return decodeXprTransaction(input, context);
  },

  generateKeyPair: generateK1KeyPair,

  createSigner(wiring: ChainWiring, keys: PrivateKeyProvider) {
    return new XprTransactionSigner({ ...wiring, privateKeyProvider: keys });
  },

  createBroadcaster(wiring: ChainWiring) {
    return new XprTransactionBroadcaster(wiring);
  },

  createRelay(wiring: ChainWiring) {
    return new XprChainReadRelay(wiring);
  },

  createPolicyReader(wiring: ChainWiring, registryLocator: string) {
    return new ChainPolicyReader({ ...wiring, contractAccount: registryLocator });
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
};
