/**
 * XPR Network descriptors (INV-013: chain identity is always explicit).
 *
 * Chain IDs are PINNED constants, never inferred from an endpoint (INV-009).
 * Endpoints are overridable defaults; the daemon configuration may replace
 * them, the chain IDs it may not.
 */

import type { NetworkDescriptor } from "../../core/types.js";

export const XPR_CHAIN = "XPR";

export const XPR_NETWORKS: Record<string, NetworkDescriptor> = {
  mainnet: {
    network: "mainnet",
    chainId: "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0",
    endpoints: ["https://proton.greymass.com", "https://proton.eosusa.io"],
  },
  testnet: {
    network: "testnet",
    chainId: "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd",
    endpoints: ["https://testnet.protonchain.com", "https://test.proton.eosusa.io"],
  },
};
