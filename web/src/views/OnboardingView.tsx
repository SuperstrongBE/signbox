/**
 * The onboarding signing page reached from the CLI's companion link (URL hash).
 *
 * The URL fragment is UNTRUSTED input (#41): an attacker can craft one, change
 * the actions, or make the payload's `summary` lie about what will be signed.
 * So before the wallet may sign, the payload is validated against the ONE
 * documented onboarding template (validateOnboardingPayload) AND the agent
 * account's future `owner` is verified to be the AUTHORITY's real on-chain key
 * (fetched, chain-id pinned) — the account-takeover vector. The summary shown
 * is DERIVED from the validated actions, never from the payload's own field.
 * Validation is re-run immediately before signing.
 */

import { useEffect, useMemo, useState } from "react";
import { Numeric } from "@proton/js";
import { clearPayload, type OnboardPayload } from "../link";
import { connect, type Connected } from "../wallet";
import { getAccount } from "../chain/rpc";
import { NETWORKS, SIGNBOX_CONTRACT, type NetworkDescriptor } from "../networks";
import { validateOnboardingPayload, type OnboardDerived } from "@sbx-onboard/validate";

// The policy chain name for the empty deny-all doc — this companion is XPR.
const CHAIN_NAME = "XPR";

type Phase = "checking" | "invalid" | "idle" | "connecting" | "connected" | "signing" | "done" | "error";

/** Canonical PUB_K1 form, or null if unparsable — for encoding-agnostic compare. */
function normKey(key: string): string | null {
  try {
    return Numeric.publicKeyToString(Numeric.stringToPublicKey(key));
  } catch {
    return null;
  }
}

/**
 * Full validation. `trusted` is the COMPILED network descriptor for this
 * payload's chain id — the payload's own `endpoints`/`signboxContract` are NOT
 * trusted (a crafted fragment controls them, and a malicious RPC would forge
 * the authority key). Facts are read from the trusted endpoints only.
 */
async function verifyPayload(
  payload: OnboardPayload,
  trusted: NetworkDescriptor,
): Promise<{ ok: true; derived: OnboardDerived } | { ok: false; reason: string }> {
  let authorityAccount, agentAccount;
  try {
    [authorityAccount, agentAccount] = await Promise.all([
      getAccount(trusted.endpoints, trusted.chainId, payload.summary.authority),
      getAccount(trusted.endpoints, trusted.chainId, payload.summary.agent),
    ]);
  } catch {
    return { ok: false, reason: "could not reach a trusted endpoint to verify this request" };
  }
  if (authorityAccount === null) {
    return { ok: false, reason: "the authority account does not exist on this chain" };
  }

  const structural = validateOnboardingPayload(payload, {
    chainId: trusted.chainId,
    chainName: CHAIN_NAME,
    signboxContract: SIGNBOX_CONTRACT,
    agentAccountExists: agentAccount !== null,
  });
  if (!structural.ok || structural.derived === undefined) {
    return { ok: false, reason: structural.errors[0] ?? "the request does not match a valid onboarding" };
  }

  // The owner key the payload installs MUST be the authority's real key,
  // read from a TRUSTED endpoint — the account-takeover guard.
  const authorityKey = authorityAccount.permissions.find((p) => p.perm_name === "active")?.required_auth.keys[0]?.key;
  const declaredOwner = normKey(structural.derived.ownerKey);
  const realAuthority = authorityKey !== undefined ? normKey(authorityKey) : null;
  if (declaredOwner === null || realAuthority === null || declaredOwner !== realAuthority) {
    return { ok: false, reason: "this request would hand the agent's owner to a key that is not the authority's" };
  }
  return { ok: true, derived: structural.derived };
}

export function OnboardingView({ payload }: { payload: OnboardPayload }) {
  const [phase, setPhase] = useState<Phase>("checking");
  const [derived, setDerived] = useState<OnboardDerived | null>(null);
  const [session, setSession] = useState<Connected | null>(null);
  const [txid, setTxid] = useState<string>("");
  const [error, setError] = useState<string>("");

  // The trusted network descriptor for this payload's chain id — resolved from
  // COMPILED config, never from the payload. An unknown chain id is refused.
  const trusted = useMemo(
    () => Object.values(NETWORKS).find((n) => n.chainId === payload.chainId) ?? null,
    [payload],
  );

  // Validate up front — nothing is signable until this passes.
  useEffect(() => {
    let alive = true;
    if (trusted === null) {
      setError("this request is for a chain the companion does not recognize");
      setPhase("invalid");
      return;
    }
    void verifyPayload(payload, trusted)
      .then((r) => {
        if (!alive) return;
        if (r.ok) {
          setDerived(r.derived);
          setPhase("idle");
        } else {
          setError(r.reason);
          setPhase("invalid");
        }
      })
      .catch(() => {
        if (!alive) return;
        setError("this request could not be verified");
        setPhase("invalid");
      });
    return () => {
      alive = false;
    };
  }, [payload, trusted]);

  const authorityMismatch = session !== null && derived !== null && session.actor !== derived.authority;
  const summaryLines = useMemo(() => (derived === null ? [] : describe(payload, derived)), [payload, derived]);

  async function onConnect() {
    if (trusted === null) return;
    setError("");
    setPhase("connecting");
    try {
      // Open the wallet on the TRUSTED endpoints/network, not the payload's.
      const c = await connect({ ...payload, network: trusted.network, endpoints: trusted.endpoints });
      setSession(c);
      setPhase("connected");
    } catch (e) {
      setError(errMsg(e));
      setPhase("error");
    }
  }

  async function onSign() {
    if (session === null || trusted === null) return;
    setError("");
    setPhase("signing");
    // Re-validate immediately before signing (#41): guard against any state
    // that changed since the page loaded (e.g. the account now exists).
    const recheck = await verifyPayload(payload, trusted);
    if (!recheck.ok) {
      setError(recheck.reason);
      setPhase("invalid");
      return;
    }
    try {
      const { txid: id } = await session.transact(payload.actions);
      setTxid(id);
      clearPayload();
      setPhase("done");
    } catch (e) {
      setError(errMsg(e));
      setPhase("error");
    }
  }

  return (
    <main className="shell">
      <div className="card">
        <header>
          <div className="mark" aria-hidden="true">
            <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" strokeWidth="1.8" strokeLinecap="round" strokeLinejoin="round">
              <rect x="4" y="10" width="16" height="10" rx="2"></rect>
              <path d="M8 10V7a4 4 0 0 1 8 0v3"></path>
              <path d="M12 14v2"></path>
            </svg>
          </div>
          <div>
            <h1>Authorize a new agent</h1>
            <p className="net">{payload.network} &middot; contract {payload.signboxContract}</p>
          </div>
        </header>

        {phase === "checking" ? (
          <div className="result"><p>Verifying this request against the chain…</p></div>
        ) : phase === "invalid" ? (
          <div className="result err">
            <strong>This request can’t be verified.</strong>
            <p>{error}</p>
            <p className="who">For your safety, signing is disabled. Re-run <code className="mono">signbox agent create</code> and open the fresh link it prints — don’t reuse an old or forwarded one.</p>
          </div>
        ) : (
          <>
            <dl className="summary">
              <div><dt>Agent</dt><dd>{derived!.agent}</dd></div>
              <div><dt>Authority</dt><dd>{derived!.authority}</dd></div>
              <div><dt>Permission</dt><dd>{derived!.permission}</dd></div>
              <div className="wide"><dt>Agent public key</dt><dd className="mono">{derived!.agentPublicKey}</dd></div>
            </dl>

            <div className="actions-list">
              <span className="lbl">Verified — the wallet will sign exactly {derived!.actionCount} action{derived!.actionCount === 1 ? "" : "s"}</span>
              <ul>
                {summaryLines.map((a, i) => (
                  <li key={i}><span className="an">{a.name}</span> <span className="ad">{a.detail}</span></li>
                ))}
              </ul>
            </div>

            {phase === "done" ? (
              <div className="result ok">
                <strong>Signed &amp; broadcast.</strong>
                <p>Transaction <code className="mono">{txid}</code>. Return to your terminal — SignBox confirms it on-chain and activates the agent key.</p>
              </div>
            ) : (
              <div className="controls">
                {session === null ? (
                  <button className="btn primary" onClick={onConnect} disabled={phase === "connecting"}>
                    {phase === "connecting" ? "Opening wallet…" : `Connect ${payload.network} wallet`}
                  </button>
                ) : authorityMismatch ? (
                  <div className="result warn">
                    <strong>Wrong account.</strong>
                    <p>Connected as <code>{session.actor}</code>, but this request must be signed by the authority <code>{derived!.authority}</code>. Reconnect with the right account.</p>
                    <button className="btn" onClick={() => { setSession(null); setPhase("idle"); }}>Reconnect</button>
                  </div>
                ) : (
                  <button className="btn primary" onClick={onSign} disabled={phase === "signing"}>
                    {phase === "signing" ? "Signing…" : "Sign & create agent"}
                  </button>
                )}
                {session !== null && !authorityMismatch && (
                  <p className="who">Connected as <code>{session.actor}@{session.permission}</code></p>
                )}
              </div>
            )}

            {error !== "" && <div className="result err"><strong>Failed.</strong><p>{error}</p></div>}
          </>
        )}
      </div>

      <p className="foot">SignBox never sees your keys. You sign in your own wallet; the daemon also verifies the result on-chain before activating the agent.</p>
    </main>
  );
}

/** Human summary DERIVED from the validated actions (never from payload.summary). */
function describe(payload: OnboardPayload, d: OnboardDerived): { name: string; detail: string }[] {
  const lines: { name: string; detail: string }[] = [
    { name: "newaccount", detail: `create ${d.agent}, owned by ${d.authority}` },
  ];
  if (d.ramBytes > 0) lines.push({ name: "buyrambytes", detail: `${d.ramBytes} bytes, paid by ${d.authority}` });
  lines.push({ name: "createpolicy", detail: `register an empty deny-all policy on ${payload.signboxContract}` });
  return lines;
}

function errMsg(e: unknown): string {
  return e instanceof Error ? e.message : String(e);
}
