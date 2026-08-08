/**
 * Graph → bounded declarative policy (the executed artifact).
 *
 * The graph is only the AUTHORING surface: it compiles down to the small,
 * deterministic, hashable policy document the daemon evaluates. Fail-closed
 * authoring: any node without a bounded declarative form yields a warning and
 * is NOT silently interpreted (no regex, no float math, no unbounded forms).
 */

import type { GraphNode, Wire } from "./types";
import { inboundNodes, upstream, reaches } from "./eval";

export interface CompiledRule {
  id: string;
  effect: string;
  match: Record<string, unknown>;
  limits?: Record<string, unknown>;
  providers?: unknown[];
}

export interface CompiledPolicy {
  schemaVersion: 1;
  default: string;
  chain: { name: string; chainId: string };
  maxActionsPerTransaction: number;
  rules: CompiledRule[];
}

export interface CompileResult {
  policy: CompiledPolicy;
  warnings: string[];
}

// The daemon's closed vocabularies — imported from the SAME module the
// daemon's validator uses (src/core/policy/vocabulary.ts), so the editor can
// never produce a path the daemon rejects as schema_invalid (#45).
import { MATCH_PATH_RE, SELECT_FIELD_RE } from "@sbx-core/policy/vocabulary";

function listOf(s: string): string[] {
  return s.split(",").map((x) => x.trim()).filter(Boolean);
}

function slug(parts: string[]): string {
  return parts
    .join("-")
    .toLowerCase()
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-|-$/g, "")
    .slice(0, 40) || "rule";
}

function compileRule(nodes: GraphNode[], wires: Wire[], decision: GraphNode): { rule: CompiledRule; warnings: string[]; drop: boolean } {
  const warnings: string[] = [];
  let drop = false;
  const up = [...upstream(wires, decision.id)]
    .map((id) => nodes.find((n) => n.id === id))
    .filter((n): n is GraphNode => n !== undefined);
  const match: Record<string, unknown> = {};
  const providers: unknown[] = [];
  const routeif = up.find((n) => n.type === "routeif");
  if (routeif !== undefined) {
    if (routeif.fields["contract"]) match["contract"] = routeif.fields["contract"];
    if (routeif.fields["action"]) match["action"] = routeif.fields["action"];
  }
  for (const n of up) {
    const f = n.fields;
    if (n.type === "compare") {
      const src = inboundNodes(nodes, wires, n.id, "a")[0];
      if (src !== undefined && src.type === "getfield") {
        const op = String(f["op"]);
        const value = String(f["value"]);
        const path = String(src.fields["path"]);
        // Bounded declarative forms + a valid daemon match path only.
        if (!MATCH_PATH_RE.test(path)) {
          warnings.push(`Match path “${path}” isn’t a valid field (contract, action, or data.<field>) → rule omitted`);
          drop = true;
        } else if (op === "eq") match[path] = value;
        else if (op === "lte") match[path] = { lte: value };
        else if (op === "gte") match[path] = { gte: value };
        else warnings.push(`Compare “${op}” has no bounded declarative form → rejected`);
      } else {
        warnings.push("Compare not fed by a Get Field → rejected");
      }
    } else if (n.type === "inlist") {
      const src = inboundNodes(nodes, wires, n.id, "a")[0];
      if (src !== undefined && src.type === "getfield") {
        const path = String(src.fields["path"]);
        if (!MATCH_PATH_RE.test(path)) {
          warnings.push(`Match path “${path}” isn’t a valid field (contract, action, or data.<field>) → rule omitted`);
          drop = true;
        } else {
          match[path] = f["mode"] === "notin" ? { notIn: listOf(String(f["list"])) } : { in: listOf(String(f["list"])) };
        }
      }
    } else if (n.type === "contains") {
      const gf = inboundNodes(nodes, wires, n.id, "a")[0];
      const lk = gf !== undefined && gf.type === "getfield" ? inboundNodes(nodes, wires, gf.id, "in")[0] : undefined;
      if (lk !== undefined && lk.type === "lookup" && lk.fields["mode"] === "http") {
        // Generic HTTP lookups are test-only: non-deterministic, not a daemon
        // provider. Never let one into the pushed policy.
        warnings.push("HTTP lookup is test-only and can’t be enforced by the daemon → rule omitted");
        drop = true;
      } else if (lk !== undefined && lk.type === "lookup" && gf !== undefined) {
        const select = String(gf.fields["path"]);
        if (!SELECT_FIELD_RE.test(select)) {
          warnings.push(`Lookup field “${select}” isn’t a valid row field name → rule omitted`);
          drop = true;
        } else {
          providers.push({
            provider: "xpr.rpc.tableRow",
            args: {
              contract: String(lk.fields["contract"]),
              scope: String(lk.fields["contract"]),
              table: String(lk.fields["table"]),
              key: String(lk.fields["key"]),
            },
            select,
            op: "contains",
            value: String(f["value"]),
          });
        }
      } else {
        warnings.push("Contains not fed by Lookup → Get Field → rejected");
      }
    } else if (n.type === "boolor" || n.type === "boolnot") {
      warnings.push(`“${n.type === "boolor" ? "OR" : "NOT"}” has no declarative form (match is implicit AND) → split into separate rules`);
    }
  }

  const routeBase = routeif !== undefined ? [String(routeif.fields["contract"]), String(routeif.fields["action"])] : [String(decision.fields["effect"])];
  // Preserve a loaded rule's id (#38) so a round trip is lossless; new rules
  // (no stored id) get a generated slug.
  const preservedId = typeof decision.fields["id"] === "string" ? (decision.fields["id"] as string) : "";
  const ruleId = preservedId !== "" ? preservedId : slug([String(decision.fields["effect"]), ...routeBase]);
  const rule: CompiledRule = { id: ruleId, effect: String(decision.fields["effect"]), match };

  if (decision.fields["useLimit"] === true && decision.fields["effect"] === "allow") {
    const limits: Record<string, unknown> = {};
    if (decision.fields["maxPerTx"]) limits["maxPerTransaction"] = decision.fields["maxPerTx"];
    const cooldownH = parseFloat(String(decision.fields["cooldownH"] ?? ""));
    if (!isNaN(cooldownH) && cooldownH > 0) limits["cooldownPerRecipientMs"] = Math.round(cooldownH * 3_600_000);
    const rlRaw = String(decision.fields["rlCount"] ?? "");
    if (rlRaw !== "") {
      const count = parseInt(rlRaw, 10) || 1;
      const key = decision.fields["rlPerRecipient"] === true
        ? "maxCountPerRecipientPerHour"
        : decision.fields["rlPeriod"] === "day" ? "maxCountPerDay" : "maxCountPerHour";
      limits[key] = count;
    }
    if (Object.keys(limits).length > 0) rule.limits = limits;
  }
  if (providers.length > 0) rule.providers = providers;
  return { rule, warnings, drop };
}

export function compilePolicy(nodes: GraphNode[], wires: Wire[], chainId: string): CompileResult | null {
  const policyNode = nodes.find((n) => n.type === "policy");
  if (policyNode === undefined) return null;
  const decisions = nodes
    .filter((n) => n.type === "decision" && reaches(wires, n.id, policyNode.id))
    .sort((a, b) => a.y - b.y);
  const rules: CompiledRule[] = [];
  const warnings: string[] = [];
  for (const dn of decisions) {
    const compiled = compileRule(nodes, wires, dn);
    warnings.push(...compiled.warnings);
    // Drop a rule the daemon would reject (invalid custom path/field) — the
    // warning naming it was already emitted in compileRule.
    if (compiled.drop) continue;
    // A rule whose `match` ends up empty would apply to EVERY action — the
    // daemon's schema rejects it (match needs ≥1 property) and it is unsafe
    // anyway. Omit it (safe: removing a match-everything rule only narrows the
    // policy) and tell the author which one, and how to make it valid.
    if (Object.keys(compiled.rule.match).length === 0) {
      warnings.push(
        `Rule “${compiled.rule.id}” isn’t a valid route (empty match — add a Route If, or a Compare/In List condition) → omitted from the policy.`,
      );
      continue;
    }
    rules.push(compiled.rule);
  }
  return {
    policy: {
      schemaVersion: 1,
      default: String(policyNode.fields["default"]),
      chain: { name: "XPR", chainId },
      maxActionsPerTransaction: parseInt(String(policyNode.fields["maxActions"]), 10) || 1,
      rules,
    },
    warnings,
  };
}

// THE daemon's canonicalizer (RFC 8785 JCS), same source file — the pushed
// policyjson is byte-identical to what verifyStoredPolicy re-canonicalizes.
export { canonicalize } from "@sbx-core/canonical/jcs";

export async function sha256Hex(text: string): Promise<string> {
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(text));
  return [...new Uint8Array(digest)].map((b) => b.toString(16).padStart(2, "0")).join("");
}
