/** Sample incoming transactions for the routing simulator. */

import type { Sample, SampleAction } from "./types";

function transfer(to: string, amount: string, symbol = "XPR", contract = "eosio.token"): SampleAction {
  return { contract, action: "transfer", data: { from: "agent", to, quantity: { amount, symbol } } };
}

export const SAMPLES: Sample[] = [
  { label: "Token transfer · 1 XPR → alice", actions: [transfer("alice", "1.0000")] },
  { label: "Token transfer · 5 XPR → alice", actions: [transfer("alice", "5.0000")] },
  { label: "Token transfer · 1 XPR → mallory", actions: [transfer("mallory", "1.0000")] },
  {
    label: "5× Token transfer · 1 XPR → alice",
    actions: Array.from({ length: 5 }, () => transfer("alice", "1.0000")),
  },
  {
    label: "NFT mint (atomicassets)",
    actions: [{ contract: "atomicassets", action: "mintasset", data: { from: "agent", to: "", quantity: { amount: "", symbol: "" } } }],
  },
  { label: "xUSDC transfer", actions: [transfer("bob", "10.0000", "XUSDC", "xtokens")] },
];
