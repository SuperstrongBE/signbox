# SignBox

**A local signing daemon that lets software agents use a blockchain key they can never see.**

SignBox sits between an AI agent (or any automated tool) and a blockchain private key. The agent submits transactions it would like to sign; SignBox inspects them, checks them against a deterministic policy, and either signs or refuses. The agent never touches the key — it only ever holds a limited capability: *asking for a signature*.

> Status: **specification draft v0.3 + Phase 1 implementation in progress**. Not production-ready. First target chain: [XPR Network](https://xprnetwork.org).

---

## The problem

LLM-based agents are probabilistic. Prompt injection, poisoned tools or plain misbehavior can make an agent do things it was never supposed to do. If that agent holds a private key, one successful attack means the key — and everything it controls — is gone.

Giving an agent a key is easy. Giving an agent *bounded, revocable, auditable* signing power is not. That is what SignBox does.

## How it works: the black box

To the agent, SignBox is a black box:

```
        agent / LLM
            │
            │  plain JSON actions (never bytes, never a hash)
            ▼
┌───────────────────────────┐
│         SignBox           │
│                           │
│  1. validate the JSON     │
│  2. apply the policy      │      policy source of truth:
│  3. sign or refuse        │◄──── on-chain contract,
│                           │      controlled by a superior
└───────────┬───────────────┘      authority — never by the agent
            │
            ▼
   signed transaction | refusal
```

- The agent submits **raw, unserialized JSON** — a readable list of actions. Packed transactions, hex blobs and bare digests are rejected categorically.
- It receives **a single final answer**: a signed transaction, or a refusal with a safe reason. Nothing else ever leaves the box.
- The decision is made by a **deterministic policy engine** — never by an LLM, never by a heuristic. Same input, same policy, same decision. A policy lives on-chain and can only be changed by the *superior authority* (a human wallet), never by the agent.

SignBox behaves like a **headless programmatic wallet**: it receives a readable transaction proposal — exactly as a human wallet receives a signing request — validates it, serializes it itself, and signs it with the key it protects. The only difference from a human wallet is that the approval tap is replaced by a policy.

The security consequence: **compromising the agent no longer compromises the key.** A fully hijacked agent is reduced to *proposing* transactions; its maximum blast radius is whatever the policy already allows. The cost of an attack moves from "convince an LLM" (easy) to "take over the host machine" (hard).

## What SignBox guarantees

- **Deny by default** — an empty or missing policy authorizes nothing.
- **The key never leaves the daemon** — no API, log, error or CLI command returns it. Keys are stored encrypted (Argon2id + XChaCha20-Poly1305) and live only in locked memory buffers while in use.
- **Full decoding or refusal** — SignBox never signs anything it cannot completely read: no opaque blobs, no unknown fields, no surprise second action buried in a transaction.
- **Fail closed** — any error, timeout, ambiguity or unknown value results in a refusal. There is no "probably fine" path.
- **No LLM in the decision loop** — the agent can propose and ask; only the policy engine decides.
- **Exact money math** — amounts are integers of minimal units (`bigint`), never floating point. Comparisons require an exact symbol and precision match; lookalike symbols and decimal tricks are refused, not coerced.
- **Signing and broadcasting are separate permissions** — a policy can allow signing while forbidding network effects.

## What SignBox does not guarantee

Honesty matters in a security tool:

- The boundary between agent and key is **OS-level isolation** (separate users, socket permissions, peer credentials). A root attacker — or anything running as the daemon's own user — is outside the software guarantee. Hardware-grade non-exportability requires an HSM/TPM (planned, Phase 3).
- Rate limits and daily caps are enforced **locally** and are best-effort; anything that must be absolutely guaranteed belongs on-chain.
- SignBox protects the key, not the agent's other data. What an agent legitimately knows, it can still leak.

## Two signing paths, kept strictly apart

| | Runtime signing | Onboarding / administration |
|---|---|---|
| Who signs | SignBox, with the agent's key | A human authority, with their own wallet |
| Used for | day-to-day agent transactions | creating agents, changing policies, rotating keys |
| Mechanism | policy check, then sign in-process | signing request encoded as a QR code, scanned and approved in the authority's wallet |
| Key exposure | key stays inside the daemon | SignBox never holds the authority's key |

The agent's key signs only what the policy allows. Everything administrative — including changing the policy itself — requires the external authority's wallet.

## What a policy looks like

```json
{
  "schemaVersion": 1,
  "default": "deny",
  "chain": { "name": "XPR", "chainId": "71ee83bc…" },
  "rules": [
    {
      "id": "allow-small-xpr-tips",
      "effect": "allow",
      "match": {
        "contract": "eosio.token",
        "action": "transfer",
        "data.from": "$agent",
        "data.quantity.symbol": "XPR",
        "data.quantity.amount": { "lte": "1000.0000" },
        "data.to": { "notIn": ["blocked.gm"] }
      },
      "limits": {
        "maxPerTransaction": "1000.0000 XPR",
        "maxPerDay": "5000.0000 XPR"
      }
    }
  ]
}
```

Declarative, versioned, JSON-Schema-validated, no executable code. An explicit `deny` always beats an `allow`; anything not explicitly allowed is refused.

## Project status & roadmap

| Phase | Scope | Status |
|---|---|---|
| Spec | Architecture & security specification ([docs/](docs/)) | ✅ draft v0.3 |
| 1 — XPR MVP | Core engine, encrypted keystore, daemon, XPR adapter, on-chain policy contract, CLI, MCP server | 🚧 in progress |
| 2 — Hardening | Dedicated OS user, RPC quorum, signed releases, fuzzing, external audit | planned |
| 3 — High assurance | HSM/TPM/PKCS#11 backends, attestation, administrative multisig | planned |
| 4 — More chains | Additional `ChainAdapter` implementations (the core is chain-agnostic from day one) | planned |

## Development

Requirements: Node.js ≥ 22.

```bash
npm install
npm test        # unit + adversarial test suite
npm run build   # compile TypeScript
```

The full architecture and threat model live in [`docs/signbox-spec-v0.3-complete.md`](docs/signbox-spec-v0.3-complete.md). Start with §1.1 — it is the reading key for everything else.

## License

Not yet licensed for public use — this repository is under active early development.
