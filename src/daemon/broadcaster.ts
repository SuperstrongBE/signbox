/**
 * Broadcast seam for the daemon-owned submit path (spec §5.5, §13).
 *
 * When an agent asks SignBox to *submit* (not merely sign), SignBox owns the
 * whole lifecycle: it signs, broadcasts, and only then decides what happens to
 * the reserved stateful quota. The signature never leaves the daemon on this
 * path, so the broadcast outcome maps cleanly onto the quota:
 *
 *  - `accepted`  → the tx landed; the reservation is committed.
 *  - `rejected`  → a DETERMINISTIC chain rejection (insufficient NET/CPU/RAM,
 *                  an eosio_assert, a bad auth, an expired tx). The tx did NOT
 *                  land and the signed bytes are discarded here, so there is no
 *                  replay path: the reservation can be released safely.
 *  - `ambiguous` → a transport/unknown failure (timeout, connection reset). We
 *                  cannot tell whether the node applied it, so the reservation
 *                  is KEPT (fail closed on quota — never risk a double-spend).
 */

import { JsonRpc } from "@proton/js";
import { pinChainId } from "../chains/xpr/adapter.js";

export type BroadcastOutcome =
  | { status: "accepted"; receipt: unknown }
  | { status: "rejected"; reason: string }
  | { status: "ambiguous"; reason: string };

export interface TransactionBroadcaster {
  broadcast(signedTransaction: unknown): Promise<BroadcastOutcome>;
}

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

    const rpc = new JsonRpc(this.options.endpoints);
    pinChainId(rpc, this.options.chainId);
    try {
      await rpc.get_info(); // validates the pinned chain id before any broadcast
      const receipt = await rpc.push_transaction({
        signatures: payload.signatures,
        serializedTransaction: Uint8Array.from(Buffer.from(payload.packedTransaction, "hex")),
      });
      return { status: "accepted", receipt };
    } catch (error) {
      // A structured node error (eosjs RpcError, carrying `.json`) means the
      // node evaluated and REJECTED the tx — deterministic, did not land. A
      // bare transport error (no response) is ambiguous.
      return isDeterministicRejection(error)
        ? { status: "rejected", reason: reasonOf(error) }
        : { status: "ambiguous", reason: reasonOf(error) };
    }
  }
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
