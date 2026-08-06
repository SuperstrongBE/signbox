/**
 * Resolves the deterministic async provider queries a policy needs (spec §8.4),
 * turning each into evidence the PURE engine then evaluates. This is the only
 * place that touches the network for policy evaluation; the engine never does.
 *
 * Everything fails closed: an unreachable relay, a timeout, or a malformed
 * response yields `{ ok: false }`, which the engine maps to a refusal
 * (PROVIDER_UNAVAILABLE). A successful query that finds no row is a valid,
 * deterministic "not found" — distinct from "could not resolve".
 */

import type { ChainReadRelay } from "./chainRelay.js";
import type { PolicyDialect } from "../core/policy/dialect.js";
import type { ProviderEvidence, ProviderEvidenceMap, ProviderQuery } from "../core/policy/engine.js";

const DEFAULT_TIMEOUT_MS = 3000;

export async function resolveProviders(
  queries: ProviderQuery[],
  relay: ChainReadRelay | undefined,
  dialect: PolicyDialect,
  timeoutMs: number = DEFAULT_TIMEOUT_MS,
): Promise<ProviderEvidenceMap> {
  const evidence: ProviderEvidenceMap = {};
  await Promise.all(
    queries.map(async (query) => {
      evidence[query.key] = await resolveOne(query, relay, dialect, timeoutMs);
    }),
  );
  return evidence;
}

async function resolveOne(
  query: ProviderQuery,
  relay: ChainReadRelay | undefined,
  dialect: PolicyDialect,
  timeoutMs: number,
): Promise<ProviderEvidence> {
  if (relay === undefined) return { ok: false };
  try {
    // The QUERY→read-call mapping is the dialect's (#45); the timeout and the
    // fail-closed catch are generic and stay here.
    return await withTimeout(dialect.resolveProviderQuery(query, relay), timeoutMs);
  } catch {
    return { ok: false };
  }
}

function withTimeout<T>(promise: Promise<T>, ms: number): Promise<T> {
  return new Promise<T>((resolve, reject) => {
    const timer = setTimeout(() => reject(new Error("provider timeout")), ms);
    promise.then(
      (value) => {
        clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        clearTimeout(timer);
        reject(error instanceof Error ? error : new Error(String(error)));
      },
    );
  });
}
