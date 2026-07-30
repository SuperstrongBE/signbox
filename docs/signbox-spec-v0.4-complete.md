# SignBox — Architecture and Security Specification

**Status:** Draft v0.4 (Phase 1 implementation)  
**Date:** 2026-07-30  
**Initial target:** XPR Network (ChainAdapter architecture from V1)  
**Recommended implementation:** TypeScript / Node.js or Bun  
**Concept author:** Rockerone / Railgun ecosystem

> **v0.2 → v0.3:** "black box" model made explicit (§1.1); new invariant INV-014 "unserialized JSON input only"; explicit separation of the two signing paths (§5.5); `packedTransaction` removed from the API (§12.1); actual role of the contract reframed (§7.5); canonicalization pinned (§8.6); quotas declared best-effort (§8.5); anti-rollback and local kill-switch (§14.5–14.6); mandatory peer credentials (§12.3); exhaustive field inspection (§15.5).
>
> **v0.3.1:** §12.3 reworked into **layered local authentication** — Node.js does not expose `SO_PEERCRED`/`getpeereid`, so the MVP proves caller identity through token-file possession (a userspace equivalent), and the native kernel-level peer-credential check becomes an additional Phase 2 hardening layer. `token` field added to `SignRequest` (§12.1).
>
> **v0.4 (implementation deltas):** decisions locked while building the Phase 1 MVP.
> - **Zero-config.** The daemon takes no agents/policies configuration. Agents are discovered from the encrypted keystores it holds (their agent name and chain come from the keystore's authenticated metadata); policies come from the on-chain contract through the cache. An optional config file covers deployment settings only (network, endpoints, contract account, paths), defaulting under `~/.signbox/`. There is no local `policy.json` in the trust path (INV-004, §15.2).
> - **On-chain contract.** `createpolicy` requires the initial version to be 1; `setpolicy` requires a strictly increasing version (the on-chain source of the daemon's anti-rollback); `sha256(policyjson) == policyhash` is verified on-chain, made possible by requiring the stored JSON to already be canonical JCS bytes (§8.6); the authority pays the row's RAM; `setauthority` requires the current AND new authority to co-sign. The contract never parses the policy JSON — the daemon is the sole validator (§7.5).
> - **Onboarding (§10).** Two modes: create a new agent account, or onboard an existing one. The agent's `owner`/`active` are controlled by the authority via an account permission (no authority key needed); the SignBox key lives on a dedicated permission, child of `active`; `linkauth` is out of scope (the developer links it per policy). Session timeout = 2 minutes (the XPR wallet window). The `agent create` CLI is interactive, prompting for chain (XPR only), network, authority, agent, mode and key export policy; flags remain for scripted use.
> - **Policy cache freshness.** 30 s background refresh; financial policies re-confirmed within 10 s; strict fail-closed (§14.3–14.4). Anti-rollback watermark persisted across restarts (§14.5).
> - **Multi-action limit hardening (§8.7).** `maxPerTransaction` now aggregates the SUM of a rule's matching actions in the transaction (not per action); new top-level `maxActionsPerTransaction` (default 1) refuses multi-action transactions unless the policy opts in; new count-based rate limits `maxCountPerHour` / `maxCountPerDay` / `maxCountPerRecipientPerHour`, counting each action.
> - **Audit & agent surfaces implemented (§16, §11.7).** The audit trail is a hash-chained SQLite log (each entry embeds the previous entry's hash; `signbox audit verify` detects any edit or deletion), recording only the decision, `contract::action` names, rule ids, policy version and digest — never a secret or transaction data. The official MCP server ships the minimal safe tool surface (list/info/inspect/explain/sign, and push only when explicitly enabled), plus `llms.txt` / `llms-full.txt`.
> - Open questions #2, #3, #4, #5 and #10 are resolved accordingly (§19).
>
> **Phase 1 (XPR MVP) is functionally complete** as of this revision: engine, keystore, JSON decoding, daemon, XPR signing, quotas, on-chain policy contract + anti-rollback cache, interactive ESR onboarding, zero-config, multi-action hardening, hash-chained audit, and the MCP server — all implemented and tested (190 tests: 178 daemon + 12 contract).

---

## 1. Executive summary

SignBox is a local controlled-signing daemon intended for software agents and automated tools.

Its role is deliberately minimal:

1. hold an agent's private key without ever exposing it to the agent;
2. receive an unsigned transaction;
3. fully decode it;
4. apply a deterministic policy;
5. sign or refuse;
6. return only a signature or a signed transaction.

The agent never obtains the private key. It obtains a limited capability: **requesting a signature**.

SignBox is not a general-purpose wallet, an LLM, a business engine, or a blockchain authority. It is a deterministic security boundary between a potentially compromised agent and a blockchain key.

### 1.1 Fundamental model: the black box

**This section is the reading key for the entire spec. Any interpretation that contradicts it is a misreading.**

To the agent, SignBox is a **black box**:

- the agent submits actions as **raw, unserialized JSON** — never a packed transaction, never bytes, never a hash (INV-014);
- it receives **a single final response**: a signed transaction, or a refusal with a safe reason;
- nothing else leaves the box: no key, no internal state, no policy details beyond what is necessary.

SignBox behaves like a **headless programmatic wallet**. It receives a readable transaction proposal — exactly as a human wallet receives an ESR request — validates it, serializes it itself, and signs it with the key it protects. The only difference from a human wallet: the approval tap is replaced by a deterministic policy engine.

Central security consequence: **SignBox decouples agent compromise from key compromise.** A fully compromised agent (prompt injection, hijacked LLM, poisoned tool) is reduced to *proposing* transactions; its maximum blast radius is the envelope already authorized by the policy. It can neither widen that envelope nor reach the key: both live on the other side of a process boundary it does not cross. The cost of an attack moves from "convincing an LLM" (easy, probabilistic) to "taking control of the host" (hard, categorical).

Honest limits of this guarantee:

- the boundary is enforced by OS isolation (separate users, socket permissions, peer credentials — §5.1, §12.3): it is only as strong as that isolation. A root attacker, or any process running under the same UID as the daemon, makes the box transparent (§9.3);
- SignBox protects the key and the signing authority. It does not protect information the agent legitimately holds elsewhere (business data, application content): out of scope by construction (INV-012).

### Technology decision

The MVP and the first production version must be written in **TypeScript**.

Reason: the required XPR ecosystem already exists in JavaScript/TypeScript: RPC, transaction serialization, PSR/ESR, action building, key generation and signing. A Rust version would force rebuilding, porting or wrapping these building blocks before even working on SignBox's own value.

Rust remains a future option for:

- an isolated policy engine;
- a native software enclave;
- a high-assurance version;
- an HSM/PKCS#11 backend;
- a rewrite justified by measurements or an audit.

**Roadmap invariant:** no Rust rewrite must be planned before the concrete limits of the TypeScript version have been measured.

---

## 2. Goals

### 2.1 Functional goals

SignBox must make it possible to:

- create an XPR agent account from a CLI;
- generate an agent-specific key;
- store that key in encrypted form;
- create a dedicated XPR permission;
- register a policy on-chain in a central SignBox contract;
- request the signature of a transaction from an agent or an MCP;
- automatically refuse any transaction outside the policy;
- rotate, revoke or replace the agent's key;
- modify a policy only through the superior authority;
- keep a complete local audit trail without logging secrets.

### 2.2 Security goals

- The private key never leaves the signing process after import or generation.
- The agent has no read access to the secret.
- The agent cannot modify its own policy.
- A missing, invalid, expired or unloadable policy results in a total refusal.
- A transaction that cannot be fully decoded results in a refusal.
- Native XPR limits and SignBox limits are cumulative.
- Key rotation always remains possible through the superior authority.
- Compromise of the LLM must not be sufficient to extract the secret or widen its rights.

### 2.3 Non-goals of the MVP

- Implementing several chains in the first version. The core is nevertheless structured around `ChainAdapter` from V1.
- Mandatory hardware HSM.
- Distributed consensus between several SignBox instances.
- Consumer wallet.
- Full graphical account-creation interface.
- Turing-complete policy language.
- Human approval for every transaction.

---

## 3. Actors and responsibilities

### 3.1 Superior authority

Example: `superdev`.

It:

- controls the agent's `owner` account;
- creates the agent;
- approves the initial registration;
- modifies the policy;
- performs key rotation;
- can permanently revoke the agent.

The superior authority never provides its private key to SignBox. It signs administrative operations through an external wallet and a PSR/ESR.

### 3.2 Agent

Example: `superagent`.

It:

- builds or receives unsigned transactions;
- asks SignBox to sign them;
- receives a refusal or a signed transaction;
- may broadcast the signed transaction to the network if that responsibility has been granted to it.

It cannot:

- read the private key;
- change the policy;
- change the authority;
- modify the daemon configuration;
- request an opaque signature that SignBox cannot decode.

### 3.3 SignBox daemon

It:

- loads the encrypted key;
- loads and verifies the on-chain policy;
- verifies the identity of the requesting agent;
- decodes the transaction;
- evaluates the rules;
- signs or refuses;
- logs the decision.

It does not:

- choose the agent's goals;
- modify policies;
- publish policies;
- expose the key;
- trust declarative fields provided by the agent without recomputing them.

### 3.4 SignBox contract

Single central contract, independent from the agents' business contracts.

It:

- associates an agent account with its superior authority;
- stores the canonical policy;
- enforces authorization for creation and mutation;
- prevents duplicates;
- exposes a public, deterministic state.

---

## 4. Non-negotiable invariants

### INV-001 — Deny by default

An empty or missing policy means: **no transaction authorized**.

### INV-002 — Secret never transmitted

No API, command, log, error or event returns the private key.

### INV-003 — Mandatory decoding

SignBox never signs:

- an arbitrary hash;
- an opaque blob;
- a partially decoded transaction;
- a transaction whose required ABI cannot be found;
- a transaction whose chain or chain ID does not match the configuration.

### INV-004 — Policy not modifiable by the agent

The agent/MCP process has no write access:

- to the SignBox configuration file;
- to the keystore;
- to the administration sockets;
- to the policy contract;
- to the authority identifiers.

### INV-005 — External authority

Any administrative on-chain mutation is signed by the superior authority through PSR/ESR or an external wallet. SignBox does not hold the authority's key.

### INV-006 — Double barrier

A transaction must satisfy:

1. XPR permissions and `linkauth`;
2. the SignBox policy.

The most restrictive level always wins.

### INV-007 — Irreversible non-exportable property

A key created in `non-exportable` mode never becomes exportable.

A rotation may create a new key with a different property, but never modifies the property of the old key.

### INV-008 — No decision authority granted to the LLM

No security decision depends on an LLM, a prompt, probabilistic reasoning or a field asserted by the agent.

The LLM may only:

- propose a transaction;
- request an explanation;
- receive a structured decision;
- orchestrate application tools.

The SignBox engine decides alone, from decoded data and deterministic providers.

### INV-008-A — Asynchronous providers, deterministic result

A rule may perform asynchronous RPC or HTTP reads, but:

- the provider is explicitly declared in the policy;
- the parameters are built by SignBox, never from free text provided by the LLM;
- the response is schema-validated;
- timeouts, errors, ambiguous or inconsistent responses result in a refusal;
- no provider is allowed to widen the rights defined by the policy;
- the returned data is used as deterministic predicates.

Examples: on-chain balance, current time, contract state, presence of an account in a signed remote allowlist.

### INV-009 — No trust in a single RPC

The daemon must be able to use several RPC endpoints and verify:

- the chain ID;
- the identity of the contract;
- the consistency of the response;
- the age of the policy.

### INV-010 — Fail closed

Any exception, timeout, unknown ABI, invalid rule, ambiguous synchronization state, unavailable provider or cryptographic error results in a refusal.

### INV-011 — Signing / broadcasting separation

The ability to sign and the ability to broadcast a transaction are two distinct permissions.

- `sign` produces no blockchain network effect;
- `push` broadcasts an already-signed transaction;
- `sign --push` is an explicit shortcut, never the implicit behavior;
- a policy may allow `sign` while forbidding `push`.

### INV-012 — SignBox does not know the application logic

SignBox knows neither Railgun, nor IonDrive, nor a chat, nor a game, nor a tip.

- the application builds the transaction;
- the application MCP exposes business operations to the agent;
- SignBox inspects, authorizes and signs;
- Railgun transports messages;
- IonDrive observes on-chain effects.

### INV-013 — Explicit chain and network identity

Every identity, policy, key, transaction and audit entry is bound to the triplet:

- `chain`;
- `network`;
- `chainId`.

No command must silently infer the network from an unverified endpoint.

### INV-014 — Unserialized JSON input only

SignBox only accepts transactions as **raw, unserialized JSON**: a list of readable actions with a structured, decoded `data` field.

- no packed transaction is ever accepted — by any API, in any form;
- no pre-serialized hex `data` field is accepted: `data` is always a JSON object;
- serialization into signable bytes is performed exclusively by SignBox, through the ChainAdapter, after the policy decision;
- nothing is mutated between the policy decision and the signing call: SignBox signs exactly what it validated.

This invariant guarantees "what is inspected is what is signed" by construction: there is only one representation of the transaction on the input side, and it is the one the policy evaluates.

---

## 5. Proposed architecture

```text
┌──────────────────────────────┐
│ Agent / LLM                  │
│ orchestrates, does not decide│
└──────────────┬───────────────┘
               │ MCP tools
       ┌───────┴────────┐
       ▼                ▼
┌───────────────┐  ┌──────────────────┐
│ App MCP       │  │ SignBox MCP      │
│ business logic│  │ minimal surface  │
└───────┬───────┘  └────────┬─────────┘
        │ transaction       │ SignRequest
        └────────────┬──────┘
                     ▼
┌──────────────────────────────────────────┐
│ SignBox daemon                           │
│                                          │
│ Request Authenticator                    │
│          ↓                               │
│ ChainAdapter registry                    │
│          ↓                               │
│ Transaction Decoder                      │
│          ↓                               │
│ Deterministic Policy Engine              │
│          ↓                               │
│ Async Providers (RPC / HTTP / time)      │
│          ↓                               │
│ Key Backend                              │
│          ↓                               │
│ Signature Provider                       │
└──────────────┬───────────────────────────┘
               │ signature / signed tx / refusal
               ▼
┌──────────────────────────────────────────┐
│ App / MCP broadcasts via RPC, or         │
│ explicit `signbox transaction push`      │
└──────────────────────────────────────────┘

      policy source of truth
┌──────────────────────────────────────────┐
│ SignBox XPR contract (V1 adapter)        │
│ on-chain policies per agent              │
└──────────────────────────────────────────┘
```

### 5.1 Separate processes

The SignBox daemon and the agent must run under distinct OS users.

Linux example:

- `signbox` user: access to the secret and the socket;
- `agent-superagent` user: access only to the request socket;
- root: machine administration, considered total authority.

### 5.2 Local transport

Order of preference:

1. Unix domain socket on Linux/macOS;
2. Named pipe on Windows;
3. loopback TCP with mTLS only if necessary;
4. no public network listening by default.

### 5.3 Responsibility boundaries

| Component | Responsibility | Must never do |
|---|---|---|
| Application MCP | Expose business operations, build transactions, publish UX statuses | Read a SignBox key or make security decisions |
| SignBox MCP | Adapt the daemon's local API to the MCP protocol | Invent a transaction or bypass a policy |
| SignBox daemon | Decode, evaluate, sign/refuse, optionally broadcast on explicit request | Know the business semantics of a tip, a game or Railgun |
| Railgun | Real-time transport between clients and applications | Sign blockchain transactions |
| IonDrive | Observe and republish on-chain effects | Authorize a transaction |
| ChainAdapter | Know the formats, RPC, signatures and networks of a chain | Modify the generic engine |

### 5.4 ChainAdapter architecture from V1

The core contains no XPR-specific vocabulary in its public contracts.

```ts
interface ChainContext {
  chain: string;
  network: string;
  chainId: string;
}

interface AccountIdentity {
  accountIdentifier: string;
  permission?: string;
}

interface ChainAdapter {
  readonly chain: string;
  listNetworks(): Promise<NetworkDescriptor[]>;
  resolveChainId(network: string): Promise<string>;
  decodeTransaction(input: unknown, context: ChainContext): Promise<DecodedTransaction>;
  signTransaction(input: SignableTransaction, key: KeyHandle): Promise<SignedTransaction>;
  pushTransaction?(input: SignedTransaction, context: ChainContext): Promise<PushReceipt>;
  readPolicy?(agent: AccountIdentity, context: ChainContext): Promise<CanonicalPolicyRecord>;
  buildAgentOnboarding?(input: AgentOnboardingInput): Promise<ExternalSigningRequest>;
}
```

V1: only `XprChainAdapter` is implemented and exposed.

The CLI therefore does not present a fake multichain choice. It nevertheless already accepts `--chain`, `--network` and `--chain-id`, with explicit XPR defaults.

### 5.5 Two distinct signing paths

SignBox contains two signing mechanics that share nothing. Confusing them is the most dangerous misreading of this spec.

| | Path 1 — Runtime signing | Path 2 — Onboarding / administration |
|---|---|---|
| Who signs | SignBox, with the agent's (masked) key | The superior authority, with its external wallet |
| Mechanics | `@proton/js`: ABI, serialization, TAPOS, digest, signature | ESR → console QR code → wallet → callback |
| Key involved | agent key, inside the daemon, never exposed | authority key, never held by SignBox (INV-005) |
| SignBox's role | policy gate BEFORE signing + key custody | build the ESR + verify what landed on-chain |
| Expiration | short, handled by the package (`expireSeconds`) | set by the wallet at signing time; SignBox manages a session timeout |

#### Path 1 — runtime signing

All the blockchain mechanics — ABI resolution, serialization, TAPOS, digest computation, signing — are provided by `@proton/js` and its `JsSignatureProvider`, connected to the configured RPC. **This spec does not redefine those mechanics: they are delegated to the package.**

SignBox's own responsibilities on this path reduce to three things:

1. hosting the `JsSignatureProvider` with the agent's decrypted key **inside the daemon process**, out of the agent's reach;
2. evaluating the policy on the received JSON **before** any signing call to the package;
3. mutating nothing between the policy decision and the signing call: the object handed to the package is exactly the validated object.

The choice of RPC endpoints feeding the package (ABI, ref block) is a matter of daemon configuration and INV-009.

#### Path 2 — onboarding and administration

On this path, **SignBox signs nothing**. It builds the administrative transaction, encodes it as an ESR, displays the QR code in the server console, and waits for the authority to sign it with its own wallet.

The transaction's TAPOS and expiration are resolved by the **authority's wallet at signing time**, not by SignBox. The QR does not embed a frozen TAPOS.

SignBox does however manage:

- **a session timeout**: if the QR is not signed within the window, the operation is aborted and the temporary key container is destroyed (§10.3);
- **post-landing verification**: before promoting the key and considering the agent active, SignBox verifies on-chain that what was executed matches exactly what it encoded in the ESR — account, permission, `linkauth`, policy row (§10.2, step 12). A transaction modified in transit must never go unnoticed.

---

## 6. Implementation choice: TypeScript

### 6.1 Why TypeScript

The critical XPR path is already available:

- XPR RPC and API;
- action and transaction serialization;
- `JsSignatureProvider`;
- PSR/ESR;
- callback WebSocket;
- key generation and verification;
- existing integration in the XPR CLI.

The MVP must reuse these tools, not reimplement them.

### 6.2 Runtime

Recommendation:

- strict TypeScript;
- Node.js LTS as the reference runtime;
- Bun supported after compatibility testing;
- ESM;
- committed lockfile;
- reproducible build.

### 6.3 Rust later

Rust can be introduced behind stable interfaces:

```ts
interface PolicyEvaluator {
  evaluate(transaction: DecodedTransaction, policy: Policy): Decision;
}

interface KeyBackend {
  signDigest(keyId: string, digest: Uint8Array): Promise<Uint8Array>;
}
```

Future options:

- N-API addon;
- Rust sidecar process;
- WebAssembly library for pure policy;
- PKCS#11/HSM backend.

The CLI and XPR integration can remain TypeScript even if the vault or the engine become native.

---

## 7. XPR `signbox` contract

### 7.1 Conceptual structure

```ts
interface AgentPolicyRow {
  agent: Name;                 // agent's XPR primary key
  authority: Name;             // superior authority's accountIdentifier on XPR
  agentPermission: Name;       // dedicated permission used by SignBox
  policyVersion: u32;
  policyHash: Checksum256;      // hash of the canonical JSON
  policyJson: string;          // or external storage + hash if size is excessive
  enabled: boolean;
  createdAt: u64;
  updatedAt: u64;
}
```

### 7.2 Primary key

The primary key is the agent's real XPR account name, not a free-form alias.

This prevents ambiguous squatting of a logical name: the blockchain account is the identity.

### 7.3 Actions

#### `createpolicy`

Creates the initial row with an empty policy.

Preconditions:

- `requireAuth(authority)`;
- `agent` exists;
- the authority matches the expected owner relationship;
- no row exists;
- `policyJson` is the canonical representation of an empty policy;
- `policyHash` matches.

#### `setpolicy`

Updates the policy.

Preconditions:

- `requireAuth(row.authority)`;
- strictly greater version;
- consistent JSON and hash;
- size limits;
- supported schema.

#### `disable`

Immediately disables all signing.

#### `enable`

Re-enables an existing policy.

#### `setperm`

Updates the permission name after a rotation or reconfiguration.

#### `setauthority`

Exceptional authority transfer.

Must be separate from `setpolicy`, explicitly signed by the current authority and ideally by the new authority.

#### `erase`

Optional administrative deletion. The preference is an irreversible disable or a tombstone in order to preserve the audit trail.

### 7.4 JSON storage or typed structure

For the MVP: canonical JSON + hash.

Risks:

- RAM cost;
- AssemblyScript parsing;
- schema migrations;
- unbounded size.

Recommended alternative if the policy grows large:

- store on-chain the hash, version, authority and a content URI;
- store the JSON in content-addressed immutable storage;
- SignBox verifies the hash before use.

For v0.1, enforce a low maximum size and a strict JSON schema.

### 7.5 What the contract guarantees — and does not

The contract cannot parse or semantically validate the policy JSON on-chain. This must be stated explicitly.

The contract guarantees:

- **authorization**: only the registered authority can mutate;
- **monotonicity**: the version can only grow;
- **integrity**: `policyHash` binds the content to the row;
- **distribution**: a single public state, readable by any daemon.

The contract does not guarantee:

- that `policyJson` is valid JSON;
- that the policy matches the schema;
- that the policy makes sense.

**The daemon is the sole policy validator.** An invalid, unparsable or off-schema on-chain policy results in a total signing refusal (INV-001, INV-010), never an attempt at interpretation.

---

## 8. Policy format

### 8.1 Principles

- canonical JSON;
- versioned;
- declarative;
- no executable code;
- no arbitrary dynamic expressions;
- deterministic;
- validated by JSON Schema;
- same inputs → same decision.

### 8.2 Example

```json
{
  "schemaVersion": 1,
  "default": "deny",
  "maxActionsPerTransaction": 1,
  "chain": {
    "name": "XPR",
    "chainId": "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd"
  },
  "rules": [
    {
      "id": "allow-small-xpr-tips",
      "effect": "allow",
      "match": {
        "contract": "eosio.token",
        "action": "transfer",
        "authorization.actor": "$agent",
        "authorization.permission": "$agentPermission",
        "data.from": "$agent",
        "data.quantity.symbol": "XPR",
        "data.quantity.amount": {"lte": "1000.0000"},
        "data.to": {"notIn": ["blocked.gm", "xyz"]}
      },
      "limits": {
        "maxPerTransaction": "1000.0000 XPR",
        "maxPerHour": "2500.0000 XPR",
        "maxPerDay": "5000.0000 XPR",
        "cooldownPerRecipientMs": 60000,
        "maxCountPerHour": 20,
        "maxCountPerRecipientPerHour": 3
      }
    },
    {
      "id": "deny-xusdc",
      "effect": "deny",
      "match": {
        "contract": "xtokens",
        "action": "transfer",
        "data.quantity.symbol": "XUSDC"
      }
    }
  ]
}
```

### 8.3 Evaluation order

Recommendation:

1. structural validation;
2. applicable `deny` rules;
3. applicable `allow` rules;
4. cumulative limits;
5. global default.

An explicit `deny` always wins over an `allow`.

### 8.4 Asynchronous deterministic providers

A policy may reference external state providers without delegating the decision to the agent.

Conceptual example:

```json
{
  "effect": "allow",
  "when": {
    "all": [
      {"path": "actions[0].name", "op": "eq", "value": "transfer"},
      {
        "provider": "xpr.rpc.balance",
        "args": {"account": "$agent.accountIdentifier", "symbol": "XPR"},
        "op": "gte",
        "value": "100.0000 XPR"
      },
      {"path": "actions[0].data.quantity", "op": "lte", "value": "10.0000 XPR"}
    ]
  }
}
```

The engine follows this pipeline:

1. validate the rule schema;
2. build the arguments from allowed typed variables;
3. call the provider with a strict timeout;
4. validate the response;
5. normalize units;
6. evaluate the operator;
7. refuse on any ambiguity.

Recommended V1 providers:

- `xpr.rpc.account`;
- `xpr.rpc.balance`;
- `xpr.rpc.tableRow`;
- `system.time`;
- `http.json` disabled by default and origin-allowlisted.

A generic HTTP provider is more dangerous than a typed RPC provider. It must require: allowlisted URL, fixed method, response schema, size limit, no redirects and valid TLS.

### 8.5 Required state

Some rules are stateful:

- amount per hour/day;
- recipient cooldown;
- transaction count;
- anti-replay.

The daemon must maintain a transactional local journal, for example SQLite.

Evaluation and consumption recording must be atomic in order to prevent two concurrent requests from bypassing a cap.

**SignBox quotas are a best-effort local guarantee, not a chain guarantee.** Unlike XPR permissions and `linkauth` (chain-enforced), hourly/daily caps and cooldowns live only in the daemon's local state:

- a restore or loss of the local journal resets the counters;
- two misconfigured daemon instances keep independent counters;
- the quota is consumed **at signing time**, not at broadcast time: a transaction signed but never pushed consumes quota, and a re-submission of the same digest must be recognized as idempotent before any new debit.

Any cap that must be absolutely guaranteed must be enforced on-chain (contract, permission), not only in SignBox (INV-006).

### 8.6 Canonicalization

`policyHash` and any canonical hash require a canonicalization defined once and for all:

- **JSON: RFC 8785 (JCS)** — key ordering, escaping, UTF-8 encoding and number representation pinned by the standard;
- **amounts: never floating point.** Any asset amount is handled as an integer of minimal units together with the symbol and its precision (`10000` + `XPR@4`, never `1.0` as a JavaScript `number`);
- **symbols: strict comparison on the (contract, symbol, precision) triplet** — the symbol alone is not enough (homographs, fake tokens);
- any canonicalization divergence between the daemon and the publishing tool produces a hash mismatch, hence a refusal (fail closed), never a tolerance.

### 8.7 Transaction and rate limits

**`maxActionsPerTransaction`** is a top-level policy field. It bounds the number of actions in a single transaction and **defaults to 1** when omitted: a multi-action transaction is refused (`TOO_MANY_ACTIONS`) unless the policy explicitly opts into more. A multi-action transaction is the vector that both multiplies value limits and smuggles a confused-deputy action (§15.5), so single-action is the safe default. (The XPR adapter additionally hard-caps a transaction at 16 actions during decoding.)

Per-rule `limits` fields:

| Field | Kind | Meaning |
|---|---|---|
| `maxPerTransaction` | asset | Maximum **total value** moved by this rule's matching actions **in one transaction** — the SUM across actions, not per action. N actions each at the cap cannot move N × the cap. |
| `maxPerHour` / `maxPerDay` | asset | Maximum total value over a sliding window (agent + rule). |
| `cooldownPerRecipientMs` | integer ms | Minimum delay between two matching actions to the same recipient. |
| `maxCountPerHour` / `maxCountPerDay` | integer | Maximum **number** of matching actions over a sliding window (agent + rule). |
| `maxCountPerRecipientPerHour` | integer | Maximum number of matching actions to the same recipient per hour. |

Semantics that matter for correctness:

- **Aggregation.** Value and count limits aggregate across the actions of a transaction. `maxPerTransaction` sums by symbol; an action whose symbol/precision does not match a rule's value cap is refused as ambiguous rather than slipping through uncapped.
- **Per-action counting.** Count and cooldown limits count **each matching action**, so a single multi-action transaction counts every action toward the window — batching cannot bypass a count limit.
- **Atomic and best-effort.** All stateful limits are reserved atomically before signing and are a local best-effort guarantee (§8.5); any absolute cap must live on-chain.

---

## 9. Key management

### 9.1 Backends

```ts
type KeyBackendKind =
  | "encrypted-file"
  | "os-keystore"
  | "pkcs11"
  | "hardware";
```

#### Backend A — encrypted file

- encryption key derived from a passphrase with Argon2id;
- authenticated encryption, e.g. XChaCha20-Poly1305 or AES-256-GCM;
- random salt;
- unique nonce;
- versioned metadata;
- `0600` file permissions;
- no passphrase in CLI arguments, environment variables or logs.

#### Backend B — OS keystore

- macOS Keychain;
- Windows Credential Manager / DPAPI;
- Linux Secret Service if available.

This mode is convenient on a local workstation, less predictable on a headless server.

#### Backend C — HSM / PKCS#11

Out of MVP scope, but interface planned.

### 9.2 Exportability

Modes at creation:

```ts
type ExportPolicy = "non-exportable" | "encrypted-backup-only";
```

- `non-exportable`: no command returns the secret;
- `encrypted-backup-only`: export of an encrypted container, never a cleartext key.

**The spec strongly discourages any plaintext export.**

### 9.3 The truth about "non-exportable"

In a purely software backend, "non-exportable" means:

- not exportable through the SignBox API;
- not displayed by the CLI;
- not saved in cleartext.

This does not protect against a root attacker able to read memory, instrument the process or replace the binary.

A strong non-exportability guarantee requires an HSM, TPM or hardware enclave.

### 9.4 Daemon unlocking

Possible modes:

1. interactive passphrase entry at startup;
2. OS keystore;
3. infrastructure secret manager;
4. HSM.

The daemon must not accept `--private-key` or `--passphrase` as arguments.

---

## 10. `signbox agent create` onboarding flow

### 10.1 User inputs

1. chain — V1 value: `XPR` only;
2. network — `mainnet` or `testnet` for XPR;
3. superior authority account (`accountIdentifier`);
4. desired agent account name (`accountIdentifier`);
5. key backend;
6. exportability property;
7. optionally a native permission strategy.

The authority's public key is resolved from the XPR account; it is not entered manually except in advanced mode.

### 10.2 Internal steps

1. Verify the chain ID and endpoints.
2. Verify that the authority account exists.
3. Verify the availability of the agent name.
4. Locally generate the agent's key pair.
5. Generate a dedicated, valid permission name.
6. Build an empty policy, `default: deny`.
7. Prepare an atomic transaction including, depending on available APIs:
   - creation of the agent account;
   - `owner` and `active` configuration under the authority's control;
   - creation of the dedicated agent permission;
   - chosen native `linkauth`;
   - `signbox::createpolicy` call with an empty policy.
8. Encode the transaction as PSR/ESR.
9. Display:
   - ASCII QR code;
   - copyable URI;
   - human-readable summary of the actions.
10. The authority signs in its usual wallet.
11. Wait for the callback or confirm the transaction via RPC, within a session timeout; beyond it, abort and destroy the temporary container.
12. Verify on-chain that the result matches exactly the emitted ESR: agent account, `owner`/`active` keys, dedicated permission, `linkauth`, policy row. Any divergence aborts the onboarding without promoting the key.
13. Encrypt and persist the private key.
14. Wipe temporary buffers as much as possible.
15. Display the agent account, the permission, the txid and the next step.

### 10.3 Secret persistence order

The key must not be lost if the on-chain operation succeeds but local storage fails.

Recommended flow:

1. generate the key;
2. immediately create a temporary encrypted container;
3. launch the ESR;
4. after confirmation, atomically promote the temporary container;
5. if the transaction fails, destroy the temporary container.

The encryption password or backend is therefore configured **before** the ESR, but the key is only considered active after on-chain confirmation.

### 10.4 Result

```text
Agent created: superagent
Authority: superdev
Permission: xp2vr3
Key backend: encrypted-file
Export policy: non-exportable
Policy: registered, default deny
Transaction: <txid>
Next: signbox policy edit superagent
```

---

## 11. CLI commands

### 11.1 General

```bash
signbox --version
signbox doctor
signbox status
```

#### `signbox doctor`

Checks:

- runtime;
- keystore access;
- file permissions;
- RPC;
- chain ID;
- SignBox contract;
- socket availability;
- system clock;
- policy schema.

### 11.2 Agent

```bash
signbox agent create [--chain XPR] [--network mainnet|testnet]
signbox agent list [--chain XPR] [--network mainnet|testnet]
signbox agent info <agent> [--chain XPR] [--network <network>]
signbox agent disable <agent>
signbox agent enable <agent>
signbox agent delete <agent>
```

`delete` must be dangerous and probably replaced by `disable` + tombstone.

### 11.3 Keys

```bash
signbox agent key rotate <agent>
signbox agent key status <agent>
signbox agent key backup <agent>
signbox agent key revoke <agent>
```

#### `key rotate`

1. generates a new key;
2. chooses its exportability property;
3. prepares the updateauth/linkauth via ESR;
4. waits for confirmation;
5. atomically switches the active key;
6. temporarily keeps the old one for controlled rollback, or destroys it per policy.

#### `key backup`

Only if `encrypted-backup-only`.

Never returns a cleartext secret.

### 11.4 Policies

```bash
signbox policy show <agent>
signbox policy validate <file>
signbox policy diff <agent> <file>
signbox policy edit <agent>
signbox policy apply <agent> <file>
signbox policy disable <agent>
signbox policy history <agent>
```

#### `policy edit`

Opens the official web editor with:

- agent;
- network;
- current policy;
- short session nonce.

The authority's wallet then signs the update transaction.

The CLI never receives the authority's key.

### 11.5 Daemon

```bash
signbox daemon start
signbox daemon stop
signbox daemon restart
signbox daemon status
signbox daemon logs
signbox daemon reload-policy
```

The daemon must not allow a policy modification through its signing API.

### 11.6 Transaction requests

```bash
signbox transaction inspect --transaction transaction.json
signbox transaction explain --agent superagent --transaction transaction.json
signbox transaction sign --agent superagent --transaction transaction.json
signbox transaction push --signed-transaction signed.json
signbox transaction sign --agent superagent --transaction transaction.json --push
```

Semantics:

- `inspect` decodes without policy and without signing;
- `explain` reads the agent's **on-chain** policy (INV-004) and evaluates the transaction against it — applying the same integrity gate as the daemon (§8.6) — without signing. It never takes a local policy file; permission and version come from the on-chain row;
- `sign` returns a signed transaction and broadcasts nothing;
- `push` broadcasts an already-signed transaction;
- `sign --push` combines both steps with explicit intent.

The default output is structured JSON. Secrets are never included.

All these commands accept the transaction **only as unserialized JSON** (INV-014). There is no option to provide a packed transaction.

`explain` evaluates the policy without signing: by construction, it is an oracle that a compromised agent can probe to map thresholds and lists. Therefore:

- `explain` is rate-limited;
- neither `explain` nor `safeReason` reveal the exact values of thresholds, lists or rules — only a refusal category.

### 11.7 Documentation and agent surfaces

SignBox must ship from the MVP:

- `llms.txt`: short capability map — **implemented (v0.4)**;
- `llms-full.txt`: full agent reference (input format, refusal codes, policy language) — **implemented (v0.4)**;
- an official MCP server (`signbox-mcp`, stdio) with the minimal safe tool surface — **implemented (v0.4)**;
- a JSON Schema reference for requests/responses — planned;
- an integration skill explaining the invariants and the correct call order — planned;
- LLM-free client examples to prove the protocol remains deterministic — planned.

Minimal MCP tools:

- `signbox_agent_list`;
- `signbox_agent_info`;
- `signbox_transaction_inspect`;
- `signbox_transaction_explain`;
- `signbox_transaction_sign`;
- `signbox_transaction_push` if explicitly enabled.

The MCP must not expose: administrative creation, key export, policy modification or rotation by default.

---

## 12. Daemon API

### 12.1 Request

```ts
interface SignRequest {
  requestId: string;
  agent: string;
  chain: string;
  network: string;
  chainId: string;
  transaction: UnsignedTransactionJson; // raw unserialized JSON — the only accepted format (INV-014)
  requestedAt: string;
  expiresAt: string;
  nonce: string;
  token: string; // rotating local token (§12.3), compared in constant time
}
```

There is **no** packed transaction field: a request containing serialized bytes, hex or a hash is rejected before any evaluation (INV-014).

### 12.2 Response

```ts
type SignResponse =
  | {
      requestId: string;
      status: "signed";
      signature: string;
      transactionDigest: string;
      signedTransaction?: unknown;
      policyVersion: number;
      providerEvidence?: ProviderEvidence[];
    }
  | {
      requestId: string;
      status: "denied";
      code: string;
      safeReason: string;
      policyVersion?: number;
    };
```

### 12.3 Local authentication

Do not rely solely on the agent name in the JSON.

Use at minimum:

- OS socket permissions (the socket file and its directory are only reachable by the daemon user and the authorized agent group);
- **caller identity proof, in two layers**:
  1. **MVP — token-file possession.** The daemon issues a rotating local token stored in a file readable ONLY by the agent's OS user (mode `0400`). Every request carries the token; the daemon compares it in constant time. Possession proves the caller can read that file — i.e. runs as that user — which is the same fact peer credentials attest, proven indirectly. This is the classic cookie-file pattern (Tor control port, Erlang distribution).
  2. **Phase 2 hardening — native peer credentials.** Node.js does not expose `SO_PEERCRED` (Linux) / `getpeereid` (macOS); reading the peer UID requires a small native binding. Once available, the kernel-level check runs on every connection as an ADDITIONAL layer — it complements the token, it does not replace it.
- anti-replay nonce;
- strict expiration.

The residual gap of the token layer alone: a token is a secret, so a copy leaked outside the agent's user context (log, backup) could be used by another LOCAL process until rotation — a scenario already narrowed by the socket permissions and bounded in time by rotation. Kernel peer credentials are a fact, not a secret, and close that gap.

The token and nonce protect against replay by a third party; they do not protect against the agent itself, which legitimately holds them. The barrier against a compromised agent is OS isolation and the policy, not the token.

The administration socket is distinct from the request socket, with permissions restricted to the `signbox` user.

Hardened option: local mTLS or Railgun session signature.

---

## 13. Decision pipeline

```text
Receive request (unserialized JSON transaction — INV-014)
  ↓
Authenticate caller (peer credentials + token)
  ↓
Validate nonce + expiry
  ↓
Resolve ChainAdapter
  ↓
Check chain + network + chainId
  ↓
Load active on-chain policy cache
  ↓
Decode complete transaction
  ↓
Resolve ABIs / schemas
  ↓
Canonicalize values and units
  ↓
Check actor + permission + key id
  ↓
Evaluate explicit deny rules
  ↓
Resolve deterministic async providers
  ↓
Validate provider evidence
  ↓
Evaluate allow rules
  ↓
Sign only, or sign+push when explicitly requested
  ↓
Reserve stateful quotas atomically
  ↓
Sign transaction digest
  ↓
Commit quota journal
  ↓
Return signature
```

If any step fails: refusal.

---

## 14. Policy cache

### 14.1 Source of truth

The SignBox contract is the source of truth.

### 14.2 Local cache

The daemon uses a cache to avoid one RPC read per signature.

The cache contains:

- agent;
- authority;
- permission;
- version;
- hash;
- validated JSON;
- last verification time;
- source endpoint.

### 14.3 Refresh

- at startup;
- periodically;
- on admin command;
- after notification/indexing if available.

A modified policy must be able to revoke rights quickly.

For financial actions, enforce a short maximum freshness.

### 14.4 RPC unavailable

Modes:

- strict: refuses as soon as the policy can no longer be confirmed;
- controlled grace: uses a signed/recent cache for a short window.

Strict mode is the default.

### 14.5 Anti-rollback

The cache refuses any policy whose version is **strictly lower** than the highest version already observed for that agent. The monotonicity enforced on-chain (§7.3) must be replicated on the daemon side: a lying RPC or a restored cache must never allow silently reverting to a more permissive version.

### 14.6 Local kill-switch

The daemon exposes a local administrative command for immediate deactivation of an agent (`signbox agent disable`), effective without an on-chain round-trip. The on-chain mutation (the contract's `disable`) remains the canonical revocation, but incident response must never depend on the latency of a hand-signed ESR.

---

## 15. Main threats

### 15.1 Prompt injection / compromised agent

Expected impact: the agent attempts malicious transactions.

Defense: deterministic policy, XPR permissions, caps, restricted socket.

### 15.2 Modification of the local policy file

Defense: the canonical policy comes from the chain; the cache contains a hash and is never authoritative on its own.

### 15.3 Modification of the SignBox binary

Possible defenses:

- signed packages;
- release checksums;
- execution under a dedicated user;
- read-only filesystem;
- future secure boot / attestation.

A root attacker remains outside the strong software guarantee perimeter.

### 15.4 Memory reading

A root/debugger attacker may target the decrypted key.

Mitigation:

- small decryption window;
- isolated process;
- core dumps disabled;
- memory locking if available;
- buffer wiping;
- future HSM.

### 15.5 Confused deputy

The agent requests a transaction that looks authorized but contains additional actions.

Defense: inspection of **all** fields of the JSON transaction, not just `actions[]`:

- non-empty `context_free_actions` → deny by default;
- unknown `transaction_extensions` → deny;
- `delay_sec` different from zero → deny by default;
- unknown field at any level → deny.

### 15.6 Cap bypass through concurrency

Defense: atomic SQLite reservations, per-agent lock, idempotence by digest.

### 15.7 Replay

Defense: nonce, expiration, already-signed digest, transaction window and local journal.

### 15.8 Malicious RPC

Defense: multiple endpoints, chain ID pinning, ABI validation, optional response comparison.

### 15.9 Incomplete rotation

Defense: transactional state `pending → onchain-confirmed → locally-active` and recovery procedures.

---

## 16. Observability and audit

Log:

- request ID;
- agent;
- digest;
- contracts/actions;
- decision;
- matching rule;
- policy version;
- timestamp;
- txid after broadcast if known.

Never log:

- private key;
- passphrase;
- decrypted keystore;
- full sensitive transaction if the confidentiality policy forbids it.

Implemented (v0.4):

```bash
signbox audit tail
signbox audit query --agent superagent --since 24h
signbox audit verify
```

The journal **is** hash-chained: each entry embeds the previous entry's hash, so any inserted, deleted or edited entry breaks the chain and is reported by `audit verify`. Entries record only the decision, `contract::action` names, matching rule ids, policy version and the transaction digest — never a key, passphrase, keystore or transaction data value.

---

## 17. Mandatory tests

### 17.1 Unit

- every policy operator;
- deny/allow precedence;
- asset parsing;
- time limits;
- JSON canonicalization;
- chain ID mismatch;
- unknown ABI;
- multi-action transaction.

### 17.2 Property-based / fuzzing

- no refused transaction can ever reach the signer;
- any unknown field results in a refusal;
- JSON ordering variation does not change the canonical hash;
- no negative amounts or overflow;
- concurrency never exceeds the caps.

### 17.3 Integration

- full ESR creation;
- wallet callback;
- rotation;
- policy update;
- daemon restart;
- partially unavailable RPC;
- simulated compromised agent.

### 17.4 Adversarial tests

- injection of a second action;
- permission change;
- wrong token contract;
- homograph symbol;
- incorrect decimals;
- recipient blacklist bypass;
- replay;
- race condition;
- chain ID substitution.

---

## 18. Roadmap

### Phase 0 — Proof of concept

- TypeScript;
- encrypted-file backend;
- a single transfer action;
- temporary local policy;
- Unix socket;
- testnet.

### Phase 1 — XPR MVP

- generic core + `XprChainAdapter`;
- SignBox contract;
- full ESR onboarding;
- on-chain policy;
- rotation;
- stateful quotas;
- audit;
- deny by default;
- typed XPR RPC providers;
- official MCP;
- `llms.txt` and `llms-full.txt`.

### Phase 2 — Production hardening

- systemd service;
- dedicated OS user;
- native peer-credential binding (`SO_PEERCRED`/`getpeereid`) as an additional authentication layer (§12.3);
- RPC quorum;
- signed updates;
- fuzzing;
- external audit;
- optional encrypted backup.

### Phase 3 — High-assurance backends

- PKCS#11;
- TPM/HSM;
- possible Rust sidecar;
- attestation;
- administrative multisig.

### Phase 4 — Additional adapters

- the generic model and the adapter registry already exist since V1;
- Sui/EVM/Nostr adapters;
- per-chain typed policies;
- no abstraction that hides the real guarantees of each chain.

---

## 19. Open questions

1. Which deployments enable the `push` MCP tool? Recommendation: disabled by default.
2. Does the contract store the full JSON or only its hash and a URI? **Resolved (v0.4):** the MVP stores the canonical JSON on-chain (size-capped), with `sha256(policyjson) == policyhash` verified on-chain because the JSON must be canonical JCS bytes (§7.5, §8.6). A hash+URI variant remains the path if policies grow large.
3. Which native `linkauth` are created by default? **Resolved (v0.4):** none — `linkauth` is OUT of the onboarding scope and is the developer's responsibility, linked per policy. The SignBox key sits on a dedicated permission that is inert on-chain until linked (§10.2).
4. Does the authority transfer require dual acceptance? **Resolved (v0.4):** yes — `setauthority` requires BOTH the current and the new authority to co-sign (§7.3).
5. What is the maximum cache freshness for financial operations? **Resolved (v0.4):** 30 s background refresh; a *financial* policy (any allow rule with value limits) is re-confirmed synchronously if older than 10 s; strict fail-closed otherwise (§14.3).
6. Must the encrypted backup exist in the MVP?
7. Is a human-approval mode needed above a threshold?
8. How to handle multi-action transactions where some actions are authorized and others are not? Recommended answer: total refusal.
9. How to handle a policy that has become incompatible with a new engine version? Recommended answer: refusal and explicit migration.
10. Is the agent account created through a sponsored API or does it require the authority's resources? **Resolved (v0.4):** the superior authority pays (its resources fund `newaccount` + `buyrambytes` and the policy row's RAM). The atomic single-transaction path is subject to an XPR spike, with a two-transaction fallback (§10.2).

---

## 20. Recommended decisions for v0.3

- **Language: TypeScript.**
- **Runtime: Node.js LTS.**
- **Transport: Unix socket.**
- **Secret: encrypted file, Argon2id + XChaCha20-Poly1305.**
- **Export: non-exportable by default; optional encrypted backup.**
- **Policy: canonical JSON, on-chain, default deny.**
- **Contract: central, one row per agent account.**
- **Administration: external wallet via PSR/ESR.**
- **Signing: local, automatic, after full decoding.**
- **Broadcast: separate from signing. `sign` never broadcasts; `push` is explicit and can be disabled.**
- **Providers: asynchronous RPC/HTTP allowed only as validated deterministic sources.**
- **Agents: official MCP and LLM documentation from the MVP.**
- **Input: raw unserialized JSON only; packed transactions are forbidden everywhere (INV-014).**
- **Runtime signing: mechanics delegated to `@proton/js`; SignBox = policy gate + key custody (§5.5, path 1).**
- **Onboarding: ESR signed by the authority's wallet; session timeout and post-landing verification mandatory (§5.5, path 2).**
- **Canonicalization: RFC 8785; amounts as integers of minimal units, never floating point (§8.6).**
- **Quotas: best-effort local guarantee; any absolute cap lives on-chain (§8.5).**
- **Policy cache: anti-rollback through monotonic version; local kill-switch for incident response (§14.5–14.6).**
- **Local authentication: layered — token-file possession in the MVP, native kernel peer credentials added in Phase 2 (§12.3).**
- **Configuration: zero-config by default; agents discovered from keystores, policies from the chain; a config file covers deployment settings only, never agents/policies (v0.4).**
- **Onboarding: two modes (create / existing); the authority pays RAM; `linkauth` left to the developer; interactive `agent create` CLI (v0.4).**
- **Multichain: `ChainAdapter` contract from V1, a single XPR implementation.**
- **Rust: postponed; interfaces prepared for a future native backend.**

---

## 21. MVP success criteria

The MVP is successful when a developer can:

1. run `signbox agent create`;
2. scan a QR code;
3. sign a single administrative transaction;
4. obtain a configured agent with a protected local key;
5. publish a policy that refuses everything except a capped XPR transfer;
6. request from an agent or an MCP the signature of a valid transfer;
7. see an invalid transfer refused with a safe reason;
8. apply an asynchronous RPC balance rule without any LLM decision;
9. sign without broadcasting, then broadcast explicitly in a second step;
10. rotate the key without exposing the old one;
11. compromise the agent process without being able to read the key or change the policy.

---

## Appendix A — Considered dependencies

To be confirmed by a technical spike:

- `@proton/js` — XPR RPC, API, serialization and signing;
- internal `ChainAdapter` abstraction;
- TypeScript MCP SDK;
- `@proton/signing-request` — PSR/ESR;
- terminal QR library;
- Argon2id library;
- XChaCha20-Poly1305/libsodium library;
- JSON Schema validator;
- SQLite;
- TypeScript CLI framework;
- structured logger with redaction.

Do not choose a crypto dependency on popularity alone. Require: active maintenance, audit or recognized usage, minimal low-level API and known tests.

## Appendix B — Separation principle

```text
Superior authority: creates, configures, revokes
Agent: requests
Policy engine: decides
Key backend: protects
Signer: signs
Blockchain: executes and audits
```

None of these components must needlessly accumulate another's responsibilities.

## Appendix C — Railgun / MCP / SignBox / IonDrive separation example

Case: an agent wants to send a tip in a chat application.

```text
LLM agent
  │
  ├─ Chat MCP: begin_tip(recipient, amount)
  │      └─ builds the canonical transaction and publishes the "in progress" UX state
  │
  ├─ SignBox MCP: transaction_sign(agent, transaction)
  │      └─ SignBox decodes, consults the policy and RPC providers, then signs/refuses
  │
  ├─ Chat MCP or RPC client: push(signed_transaction)
  │
  └─ Railgun transports real-time notifications
         IonDrive observes the on-chain mutation and produces the canonical confirmation
```

A single source of truth builds the business action: the application.

SignBox never fabricates the transaction from a natural-language intent.

## Appendix D — Conceptual provider format

```ts
interface DeterministicProvider<I, O> {
  readonly id: string;
  readonly version: string;
  execute(input: I, context: ProviderContext): Promise<O>;
  validate(output: unknown): O;
}

interface ProviderContext {
  chain: string;
  network: string;
  chainId: string;
  deadlineMs: number;
}
```

Each result used in a decision must be recordable in the audit trail in redacted, verifiable form: provider, version, canonical parameters, timestamp, normalized result and duration.

## Appendix E — Chain-agnostic naming conventions

To be used in all public APIs:

- `accountIdentifier`, never `actor` or `walletName`;
- `authorityIdentifier`, never `ownerAccount` in the core;
- `chain`, `network`, `chainId`;
- optional `permission`, defined by the adapter;
- `signedTransaction`, never `packedXprTransaction` in the core;
- `transactionDigest`, whose computation belongs to the adapter.
