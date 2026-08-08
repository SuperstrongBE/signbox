/**
 * Lossless-load guard (#38).
 *
 * The node graph is only an AUTHORING surface: it compiles down to the policy
 * document the daemon enforces. If the graph cannot fully capture a loaded
 * policy, saving it from the graph would silently drop or rewrite part of the
 * document — a removed deny rule, a dropped limit or provider, an unknown or
 * future-schema field — and the result could be materially more permissive
 * than the policy an operator reviewed.
 *
 * So a policy is only editable when it survives a round trip: decompile it to a
 * graph, recompile that graph, and require the result to be — after
 * canonicalization — byte-for-byte the policy that was loaded. This compares
 * the SEMANTIC representation before and after, never merely the UI state.
 * Anything that does not round-trip is opened read-only, preserving the
 * original document verbatim; anything unparsable is invalid.
 */

import { canonicalize } from "@sbx-core/canonical/jcs";
import { compilePolicy } from "./compile";
import { decompilePolicy } from "./decompile";
import type { GraphState } from "./store";

export type PolicyLoad =
  | { mode: "editable"; state: GraphState }
  | { mode: "readonly"; original: string; reasons: string[] }
  | { mode: "invalid"; original: string; reason: string };

/**
 * Canonical form for a SEMANTIC compare. The daemon treats an omitted
 * `maxActionsPerTransaction` as 1, so a policy that leaves it out and one that
 * sets it to 1 enforce identically — normalize both to 1 before comparing so
 * that default alone never flags a lossless policy as lossy.
 */
function normalizeForCompare(policy: Record<string, unknown>): string {
  const copy: Record<string, unknown> = { ...policy };
  if (copy["maxActionsPerTransaction"] === undefined) copy["maxActionsPerTransaction"] = 1;
  return canonicalize(copy);
}

function pretty(policyJson: string): string {
  try {
    return JSON.stringify(JSON.parse(policyJson), null, 2);
  } catch {
    return policyJson;
  }
}

export function loadPolicyForEditing(policyJson: string, chainId: string): PolicyLoad {
  let parsed: unknown;
  try {
    parsed = JSON.parse(policyJson);
  } catch {
    return { mode: "invalid", original: policyJson, reason: "the policy is not valid JSON" };
  }
  if (parsed === null || typeof parsed !== "object" || Array.isArray(parsed)) {
    return { mode: "invalid", original: pretty(policyJson), reason: "the policy is not a JSON object" };
  }
  const obj = parsed as Record<string, unknown>;

  // A newer/unknown schema version needs an explicit migration — never edit it
  // blind, which would downgrade it to what this editor understands.
  if (obj["schemaVersion"] !== 1) {
    return {
      mode: "readonly",
      original: pretty(policyJson),
      reasons: [
        `this policy declares schemaVersion ${JSON.stringify(obj["schemaVersion"])}, which this editor does not understand — editing is disabled so it cannot be downgraded`,
      ],
    };
  }

  let decompiled;
  try {
    decompiled = decompilePolicy(policyJson);
  } catch (error) {
    return {
      mode: "invalid",
      original: pretty(policyJson),
      reason: error instanceof Error ? error.message : "the policy could not be read",
    };
  }

  const recompiled = compilePolicy(decompiled.state.nodes, decompiled.state.wires, chainId);
  if (recompiled === null) {
    return { mode: "invalid", original: pretty(policyJson), reason: "the policy could not be re-derived from the editor graph" };
  }

  // The guarantee: what the editor would save === what was loaded.
  const lossless =
    normalizeForCompare(obj) === normalizeForCompare(recompiled.policy as unknown as Record<string, unknown>);
  if (lossless) {
    return { mode: "editable", state: decompiled.state };
  }

  // Prefer the specific decompile warnings (they name the exact constructs);
  // fall back to a generic reason if the drift came from something they didn't
  // flag (e.g. an unknown top-level field).
  const reasons =
    decompiled.warnings.length > 0
      ? decompiled.warnings
      : ["the editor cannot fully represent this policy — saving it from the graph would change or drop part of it"];
  return { mode: "readonly", original: pretty(policyJson), reasons };
}
