/**
 * XPR broadcaster — the chain side of the daemon-owned submit path (spec
 * §5.5, §13). See daemon/broadcaster.ts for the outcome semantics the quota
 * journal relies on (accepted → commit, rejected → release, ambiguous → keep).
 *
 * Retry/duplicate/ambiguous handling lives HERE, at the broadcast boundary
 * (#42), never in the daemon core:
 *  - A submit is NOT retried. It is not idempotent except via the chain's own
 *    transaction-id dedup, which surfaces as a duplicate (see below); retrying
 *    a transport failure could double-apply, so an ambiguous result is reported
 *    as-is and the caller keeps its quota (fail closed).
 *  - A DUPLICATE (the exact tx already in a block) means it LANDED — that is
 *    idempotent success, reported as `accepted`, not a rejection.
 */

import { JsonRpc } from "@proton/js";
import { verifiedRpc } from "./rpc.js";
import type { BroadcastOutcome, TransactionBroadcaster } from "../../daemon/broadcaster.js";

export interface XprBroadcasterOptions {
  endpoints: string[];
  chainId: string;
}

export class XprTransactionBroadcaster implements TransactionBroadcaster {
  constructor(private readonly options: XprBroadcasterOptions) {}

  async broadcast(signedTransaction: unknown): Promise<BroadcastOutcome> {
    const payload = signedTransaction as { signatures?: string[]; packedTransaction?: string };
    if (!Array.isArray(payload?.signatures) || typeof payload?.packedTransaction !== "string") {
      // We produced this; a malformed blob means nothing was sent → safe to release.
      return { status: "rejected", reason: "malformed signed transaction" };
    }

    const rpc = verifiedRpc(new JsonRpc(this.options.endpoints), { chainId: this.options.chainId });
    try {
      await rpc.get_info(); // validates the pinned chain id before any broadcast
      const receipt = await rpc.push_transaction({
        signatures: payload.signatures,
        serializedTransaction: Uint8Array.from(Buffer.from(payload.packedTransaction, "hex")),
      });
      return { status: "accepted", receipt };
    } catch (error) {
      // A duplicate means the exact tx is already in a block — it landed.
      // Idempotent success, not a rejection: report accepted so quota commits.
      if (isDuplicate(error)) {
        return { status: "accepted", receipt: { duplicate: true, reason: reasonOf(error) } };
      }
      // A structured node error (eosjs RpcError, carrying `.json`) means the
      // node evaluated and REJECTED the tx — deterministic, did not land. A
      // bare transport error (no response) is ambiguous.
      return isDeterministicRejection(error)
        ? { status: "rejected", reason: reasonOf(error) }
        : { status: "ambiguous", reason: reasonOf(error) };
    }
  }
}

/** Antelope `tx_duplicate_exception` (code 3040008): the tx is already applied. */
function isDuplicate(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  const e = error as { json?: { error?: { code?: number; name?: string } } };
  const inner = e.json?.error;
  return inner?.code === 3040008 || inner?.name === "tx_duplicate_exception";
}

function isDeterministicRejection(error: unknown): boolean {
  if (error === null || typeof error !== "object") return false;
  const e = error as { name?: string; json?: unknown };
  return e.name === "RpcError" || e.json !== undefined;
}

function reasonOf(error: unknown): string {
  const e = error as {
    json?: { error?: { what?: string; details?: { message?: string }[] } };
    message?: string;
  };
  return (
    e?.json?.error?.details?.[0]?.message ??
    e?.json?.error?.what ??
    e?.message ??
    "broadcast failed"
  );
}
