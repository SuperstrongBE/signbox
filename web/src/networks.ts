/**
 * XPR network descriptors for the companion app.
 *
 * Chain IDs are PINNED constants copied from the canonical repo source
 * (src/chains/xpr/networks.ts) — never inferred from an endpoint (INV-009).
 * The global header selector switches between these at runtime, so a single
 * build/image serves both networks.
 */

export type NetworkName = "testnet" | "mainnet";

export interface NetworkDescriptor {
  network: NetworkName;
  chainId: string;
  endpoints: string[];
  /** Explorer base URL for account/tx links. */
  explorer: string;
}

export const NETWORKS: Record<NetworkName, NetworkDescriptor> = {
  mainnet: {
    network: "mainnet",
    chainId: "384da888112027f0321850a169f737c33e53b388aad48b5adace4bab97f437e0",
    endpoints: ["https://proton.greymass.com", "https://proton.eosusa.io"],
    explorer: "https://explorer.xprnetwork.org",
  },
  testnet: {
    network: "testnet",
    chainId: "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd",
    endpoints: ["https://testnet.protonchain.com", "https://test.proton.eosusa.io"],
    explorer: "https://testnet.explorer.xprnetwork.org",
  },
};

/** Account hosting the SignBox policy contract (deployment default). */
export const SIGNBOX_CONTRACT = "signbox";
