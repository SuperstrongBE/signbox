# Endpoint trust model (#40, INV-009)

RPC responses are untrusted input. SignBox never assumes an endpoint serves
the intended chain or current state — it verifies, and refuses on doubt.

## What is enforced (src/chains/xpr/rpc.ts, `verifiedRpc`)

Every RPC the daemon builds — policy reader, read relay, broadcaster, signer,
onboarding, doctor — goes through `verifiedRpc`, which guarantees:

1. **Chain-id pin, actually executed.** Before ANY data method
   (`get_table_rows`, `get_abi`, `get_account`, `fetch`, `push_transaction`)
   runs, a `get_info` verification must have succeeded within the freshness
   window. A mismatching `chain_id` throws — there is no code path where data
   from an unverified endpoint is trusted, and failover can never silently
   land on another chain (a wrong-chain endpoint poisons the call, not the
   configuration).
2. **Liveness bound.** `get_info` responses whose `head_block_time` is absent,
   unparsable, or older than **120 s** are refused: a node frozen in the past
   must not feed policy state, TAPOS headers, or reads.
3. **Freshness window.** The verification is re-executed at most every
   **30 s** per RPC instance. Most instances are per-call (reader, relay,
   broadcaster), so in practice each operation re-verifies.
4. **Response size cap.** The agent-facing read relay refuses responses whose
   serialized size exceeds **512 KiB** — a pathological node cannot amplify
   through the daemon into the agent socket.

Complementary, pre-existing guards: the relay's strict read-method allow-list
(INV-011), the policy row's shape validation + hash/canonical/schema gate
(`verifyStoredPolicy`), the anti-rollback version watermark, and the policy
cache freshness bounds (financial 10 s / non-financial 30 s).

## Residual risks and bounds

- **Failover inside a window.** `@proton/js`'s JsonRpc may fail over between
  the verification and the data call within one 30 s window. An endpoint list
  should therefore be *homogeneous in trust*: every configured endpoint is
  expected to serve the pinned chain honestly. Shrink `freshnessMs` if your
  threat model requires a tighter bound.
- **A majority-lying endpoint set** can serve stale-but-consistent state
  within the liveness bound (120 s). High-impact operations (key rotation,
  permission changes) SHOULD be confirmed against independently-operated
  endpoints — planned with the #39 identity-binding work.

## Deployment recommendations

- Prefer **your own node** first in `endpoints`, with independent public
  endpoints as fallback.
- Do not mix networks or chains in one `endpoints` list — the pin makes this
  fail closed, not work.
- `signbox doctor` verifies reachability, the pinned chain id, head liveness
  and local clock skew (< 30 s) against the configured endpoints.
