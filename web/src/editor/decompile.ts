/**
 * Decompile a bounded declarative policy back into an editable graph — the
 * inverse of compile.ts. Fail-closed on load: anything the editor's bounded
 * node set can't represent (unknown paths/operators/limits) is reported as a
 * warning and left out, never silently approximated.
 */

import type { Fields, GraphNode, NodeType, Wire } from "./types";
import { SPECS } from "./nodeSpecs";
import type { GraphState } from "./store";

interface Rule {
  id?: string;
  effect?: string;
  match?: Record<string, unknown>;
  limits?: Record<string, unknown>;
  providers?: Provider[];
}
interface Provider {
  provider?: string;
  args?: { contract?: string; scope?: string; table?: string; key?: string };
  select?: string;
  op?: string;
  value?: string;
}
interface Policy {
  default?: string;
  maxActionsPerTransaction?: number;
  rules?: Rule[];
}

const FIELD_PATHS = new Set([
  "contract",
  "action",
  "data.from",
  "data.to",
  "data.quantity.amount",
  "data.quantity.symbol",
]);

const COL = { tx: 20, route: 240, field: 470, cond: 700, and: 920, decision: 1130, policy: 1370 };
const BAND = 300;

export interface DecompileResult {
  state: GraphState;
  warnings: string[];
}

export function decompilePolicy(policyJson: string): DecompileResult {
  const warnings: string[] = [];
  let policy: Policy;
  try {
    policy = JSON.parse(policyJson) as Policy;
  } catch {
    throw new Error("policy JSON is not valid");
  }

  let id = 1;
  const nodes: GraphNode[] = [];
  const wires: Wire[] = [];
  const add = (type: NodeType, x: number, y: number, fields?: Fields): GraphNode => {
    const node: GraphNode = { id: id++, type, x, y, fields: { ...SPECS[type].defaults(), ...(fields ?? {}) } };
    nodes.push(node);
    return node;
  };
  const wire = (from: GraphNode, fromKey: string, to: GraphNode, toKey: string) =>
    wires.push({ from: { node: from.id, key: fromKey }, to: { node: to.id, key: toKey } });

  const txn = add("transaction", COL.tx, BAND);
  const rules = Array.isArray(policy.rules) ? policy.rules : [];
  const policyNode = add("policy", COL.policy, BAND, {
    default: policy.default === "allow" ? "allow" : "deny",
    maxActions: String(policy.maxActionsPerTransaction ?? 1),
  });

  rules.forEach((rule, ri) => {
    const baseY = 40 + ri * BAND;
    const match = rule.match ?? {};
    const label = rule.id ?? `rule ${ri + 1}`;

    const routeif = add("routeif", COL.route, baseY, {
      contract: typeof match["contract"] === "string" ? (match["contract"] as string) : "eosio.token",
      action: typeof match["action"] === "string" ? (match["action"] as string) : "transfer",
    });
    wire(txn, "tx", routeif, "tx");

    // Bool-producing condition nodes, stacked in the rule's band.
    const bools: GraphNode[] = [];
    let condY = baseY + 40;

    for (const [path, spec] of Object.entries(match)) {
      if (path === "contract" || path === "action") continue;
      if (!FIELD_PATHS.has(path)) {
        warnings.push(`${label}: match path “${path}” isn't representable in the editor → skipped`);
        continue;
      }
      const gf = add("getfield", COL.field, condY, { path });
      wire(routeif, "out", gf, "in");
      const cond = matchCondition(add, wire, gf, spec, COL.cond, condY, label, warnings);
      if (cond !== null) bools.push(cond);
      condY += 90;
    }

    for (const p of rule.providers ?? []) {
      if (p.provider !== "xpr.rpc.tableRow" || p.op !== "contains") {
        warnings.push(`${label}: provider “${p.provider}/${p.op}” isn't representable → skipped`);
        continue;
      }
      const look = add("lookup", COL.route, condY + 40, {
        provider: "xpr.rpc.tableRow",
        contract: p.args?.contract ?? p.args?.scope ?? "whitelister",
        table: p.args?.table ?? "lists",
        key: p.args?.key ?? "$agent",
      });
      wire(txn, "tx", look, "tx");
      const gf = add("getfield", COL.field, condY + 40, { path: p.select ?? "allowed" });
      wire(look, "out", gf, "in");
      const contains = add("contains", COL.cond, condY + 40, { value: p.value ?? "$data.to" });
      wire(gf, "out", contains, "a");
      bools.push(contains);
      condY += 130;
    }

    const decision = add("decision", COL.decision, baseY, decisionFields(rule, label, warnings));

    // Combine the rule's conditions into the decision's `cond` input.
    if (bools.length === 1) {
      wire(bools[0] as GraphNode, "out", decision, "cond");
    } else if (bools.length > 1) {
      const and = add("booland", COL.and, baseY + (condY - baseY) / 2);
      for (const b of bools) wire(b, "out", and, "in");
      wire(and, "out", decision, "cond");
    }
    // 0 conditions → route-only rule; the decision fires on routing alone.

    wire(routeif, "out", decision, "tx");
    wire(decision, "out", policyNode, "in");
  });

  return {
    state: {
      nodes,
      wires,
      selected: txn.id,
      view: { x: 0, y: 0, z: 1 },
      nextId: id,
      fitNonce: 0,
    },
    warnings,
  };
}

function matchCondition(
  add: (type: NodeType, x: number, y: number, fields?: Fields) => GraphNode,
  wire: (from: GraphNode, fromKey: string, to: GraphNode, toKey: string) => void,
  gf: GraphNode,
  spec: unknown,
  x: number,
  y: number,
  label: string,
  warnings: string[],
): GraphNode | null {
  const path = String(gf.fields["path"]);
  if (typeof spec === "string") {
    const cmp = add("compare", x, y, { op: "eq", value: spec });
    wire(gf, "out", cmp, "a");
    return cmp;
  }
  if (spec !== null && typeof spec === "object") {
    const o = spec as Record<string, unknown>;
    for (const op of ["eq", "lte", "gte"] as const) {
      if (typeof o[op] === "string") {
        const cmp = add("compare", x, y, { op, value: o[op] as string });
        wire(gf, "out", cmp, "a");
        return cmp;
      }
    }
    if (Array.isArray(o["in"])) {
      const il = add("inlist", x, y, { mode: "in", list: (o["in"] as unknown[]).join(", ") });
      wire(gf, "out", il, "a");
      return il;
    }
    if (Array.isArray(o["notIn"])) {
      const il = add("inlist", x, y, { mode: "notin", list: (o["notIn"] as unknown[]).join(", ") });
      wire(gf, "out", il, "a");
      return il;
    }
  }
  warnings.push(`${label}: operator on “${path}” isn't representable → skipped`);
  return null;
}

function decisionFields(rule: Rule, label: string, warnings: string[]): Fields {
  const fields: Fields = { effect: rule.effect === "deny" ? "deny" : "allow" };
  const limits = rule.limits ?? {};
  const supported = new Set([
    "maxPerTransaction",
    "cooldownPerRecipientMs",
    "maxCountPerRecipientPerHour",
    "maxCountPerHour",
    "maxCountPerDay",
  ]);
  let useLimit = false;
  if (typeof limits["maxPerTransaction"] === "string") {
    fields["maxPerTx"] = limits["maxPerTransaction"] as string;
    useLimit = true;
  }
  if (typeof limits["cooldownPerRecipientMs"] === "number") {
    fields["cooldownH"] = String(limits["cooldownPerRecipientMs"] / 3_600_000);
    useLimit = true;
  }
  if (typeof limits["maxCountPerRecipientPerHour"] === "number") {
    fields["rlCount"] = String(limits["maxCountPerRecipientPerHour"]);
    fields["rlPerRecipient"] = true;
    fields["rlPeriod"] = "hour";
    useLimit = true;
  } else if (typeof limits["maxCountPerDay"] === "number") {
    fields["rlCount"] = String(limits["maxCountPerDay"]);
    fields["rlPerRecipient"] = false;
    fields["rlPeriod"] = "day";
    useLimit = true;
  } else if (typeof limits["maxCountPerHour"] === "number") {
    fields["rlCount"] = String(limits["maxCountPerHour"]);
    fields["rlPerRecipient"] = false;
    fields["rlPeriod"] = "hour";
    useLimit = true;
  }
  for (const key of Object.keys(limits)) {
    if (!supported.has(key)) warnings.push(`${label}: limit “${key}” isn't representable in the editor → kept off-graph`);
  }
  fields["useLimit"] = useLimit;
  return fields;
}
