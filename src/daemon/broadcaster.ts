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
 *
 * Chain implementations live under src/chains/<chain>/ and are resolved
 * through the chain registry (issue #44).
 */

export type BroadcastOutcome =
  | { status: "accepted"; receipt: unknown }
  | { status: "rejected"; reason: string }
  | { status: "ambiguous"; reason: string };

export interface TransactionBroadcaster {
  broadcast(signedTransaction: unknown): Promise<BroadcastOutcome>;
}
