# Sign / broadcast separation (#42)

Signing and broadcasting are **independent capabilities**. Obtaining a
signature must never, as a side effect, submit a transaction to the network;
and submitting an already-signed transaction must never reach the private key.
This lets a deployment grant least privilege — a signer that cannot broadcast,
a broadcaster that cannot sign — and contain either capability independently.

## Capabilities

Every agent has two independent grants (`AgentCapabilities`,
`src/daemon/server.ts`):

| Capability  | Default | Grants |
|-------------|---------|--------|
| `sign`      | on      | Ask the daemon to sign a transaction. |
| `broadcast` | **off** | Ask the daemon to submit — fused with a sign, or standalone. |

**Broadcast is off by default (least privilege).** A daemon-wide broadcaster
being available is *never* enough to broadcast: the agent must hold the
`broadcast` grant. There is no capability up- or down-grade — a sign-only agent
that asks to broadcast is **denied**, never silently signed; a broadcast
request never silently falls back to a client-side submit.

## Configuration (`broadcast` section, `src/cli/config.ts`)

```jsonc
{
  "broadcast": {
    "enabled": false,        // default: broadcasting is OFF entirely
    "agents": ["payments"]   // allow-list; only meaningful when enabled
  }
}
```

- `enabled: false` (the default) wires **no broadcaster** at all. Every
  broadcast — fused or standalone — is refused with `BROADCAST_UNAVAILABLE`.
  This is the switch to disable broadcast support entirely.
- When `enabled: true`, only agents named in `agents` receive the `broadcast`
  capability. An agent not listed can sign but never broadcast.

Sign and broadcast are therefore granted and revoked **independently**: editing
`agents` (or flipping `enabled`) changes who may broadcast without touching who
may sign.

## The three request shapes

1. **Sign-only** — `op` omitted (defaults to sign), `broadcast` absent/false.
   Requires `sign`. Returns the signed transaction to the caller; **no
   broadcast-related network call is made.**
2. **Fused sign + broadcast** — sign request with `broadcast: true`. Requires
   `sign` **and** `broadcast` **and** a wired broadcaster. SignBox signs and
   submits; the signature **never leaves the daemon**; the reserved stateful
   quota follows the chain outcome (§13).
3. **Standalone broadcast** — `op: "broadcast"` with a `signedTransaction`.
   Requires `broadcast` (not `sign`). Submits opaque signed bytes and
   **structurally cannot reach the signer** — a broadcast-only principal can
   never obtain a signature. Reserves no daemon quota (`quota: "none"`): the
   bytes were already policy-checked and quota-accounted at sign time.

All three authenticate with the same rotating token, are anti-replayed by
nonce, and are chain-pinned (INV-013).

## Refusal codes

| Code                    | When |
|-------------------------|------|
| `CAPABILITY_DENIED`     | The agent lacks the capability the request needs (sign, or broadcast). Raised **before** any signing or submission. |
| `BROADCAST_UNAVAILABLE` | Broadcast is requested with the capability, but the deployment wired no broadcaster (`enabled: false`). |

## Lifecycle ownership

| Step                     | Owner |
|--------------------------|-------|
| TAPOS (ref block) header | The caller building the unserialized transaction; the chain signer fills TAPOS at sign time when absent. |
| Serialization / packing  | The chain signer (`TransactionSigner`), inside the daemon, from the decoded JSON (INV-014). |
| Signing                  | The keystore backend via the signer — the key never leaves it (INV-002). |
| Submission (broadcast)   | The chain broadcaster (`TransactionBroadcaster`), only on a broadcast-capable path. |
| Confirmation             | The caller (or the onboarding flow) polling the chain; the broadcaster reports accepted/rejected/ambiguous but does not wait for finality. |

## Broadcast boundary: retries, duplicates, ambiguity

Handled inside the broadcaster (`src/chains/xpr/broadcaster.ts`), never in the
daemon core:

- **No retry.** A submit is not idempotent except via the chain's own
  transaction-id dedup. A transport failure is reported `ambiguous` and the
  caller keeps its quota (fail closed — never risk a double-spend).
- **Duplicate** (`tx_duplicate_exception`, code 3040008): the exact transaction
  is already in a block — it landed. Reported `accepted` (idempotent success),
  and the quota commits.
- **Deterministic node rejection** (an `eosio_assert`, bad auth, insufficient
  resources): reported `rejected`; the tx did not land, so the fused path
  releases its quota.
- **Ambiguous** (timeout, connection reset): reported `ambiguous`; the fused
  path keeps its quota.

## Audit

The hash-chained audit log (`src/daemon/auditLog.ts`) records every path and
distinguishes the outcomes:

- `decision: "signed"` — a sign (fused entries also carry
  `broadcast: "accepted" | "rejected" | "ambiguous"`).
- `decision: "broadcast"` — a standalone submission, with the same `broadcast`
  outcome field.
- `decision: "denied"` — with the refusal `code` (e.g. `CAPABILITY_DENIED`).

The `broadcast` field is added to the chained hash **only when present**, so
logs written before this field existed still `verify()` unchanged.
