/**
 * Read-only chain relay (agent convenience — NOT part of the trust boundary).
 *
 * An agent talks only to the daemon socket; it has no RPC of its own. This
 * relay lets it read public on-chain data (its balance, an account, a table)
 * through the daemon's pinned endpoints — WITHOUT ever gaining a way to submit
 * a transaction. Implementations are a strict allow-list of read methods:
 * anything that writes/computes state is refused, so the policy gate can never
 * be bypassed through this door (INV-011).
 *
 * Chain implementations live under src/chains/<chain>/ and are resolved
 * through the chain registry (issue #44).
 */

export interface ChainReadRelay {
  /** Call a whitelisted read-only method; throws on a disallowed method. */
  call(method: string, params: unknown): Promise<unknown>;
}
