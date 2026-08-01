/**
 * Pure graph interpreter — the issue #28 pipeline with the two-tier safety
 * model, ported from the validated prototype:
 *
 *   per action:  Route If (match/skip) → atomic nodes → Decision verdicts
 *   tx level:    ① maxActions floor (automatic, default 1)
 *                ② per-rule limits AUTO-aggregated across actions
 *                ③ optional Global cap node (cross-rule ceiling)
 *
 * No DOM, no I/O: lookups are resolved by a caller-provided resolver (the
 * editor uses a deterministic mock; a later pass can plug real chain reads).
 */

import type { GraphNode, SampleAction, Wire } from "./types";

export const SKIP = Symbol("skip");
export type Value = unknown | typeof SKIP;

export interface DecisionResult {
  node: GraphNode;
  routed: boolean;
  cond: Value;
  verdict: "allow" | "deny" | null;
  reachesPolicy: boolean;
}

export interface PerAction {
  action: SampleAction;
  decisions: DecisionResult[];
  verdict: "allow" | "deny";
  governing: GraphNode | null;
  byDefault: boolean;
}

export type DecidedBy = "maxActions" | "action" | "ruleAgg" | "globalCap" | "allow";

export interface RuleAggHit {
  decision: GraphNode;
  kind: "cap" | "rate";
  sum?: number;
  cap?: number;
  recipient?: string;
  count?: number;
  limit?: number;
  period?: string;
}

export interface GlobalCapHit {
  node: GraphNode;
  sum: number;
  cap: number;
}

export interface Evaluation {
  perAction: PerAction[];
  final: "allow" | "deny";
  decidedBy: DecidedBy;
  reason: string;
  governingId: number | null;
  maxActions: number;
  tooMany: boolean;
  ruleAgg: RuleAggHit | null;
  globalCap: GlobalCapHit | null;
  /** Node values for the action that decided (badges + wire highlight). */
  nodeValues: Map<number, Value>;
  /** Ids on the governing path (upstream cone + path to policy). */
  hotNodes: Set<number>;
  hotWires: Set<string>;
}

export type LookupResolver = (fields: Record<string, string | boolean>) => unknown;

/** Deterministic mock rows so the editor is explorable offline. */
export const mockLookup: LookupResolver = (fields) => {
  const table = String(fields["table"] ?? "");
  if (/list|whitelist/.test(table)) return { allowed: ["alice", "bob", "carol"], owner: "rockerone" };
  if (/tier/.test(table)) return { tier: "gold" };
  return { found: true };
};

export function wireKey(w: Wire): string {
  return `${w.from.node}:${w.from.key}->${w.to.node}:${w.to.key}`;
}

function inboundNodes(nodes: GraphNode[], wires: Wire[], id: number, key: string): GraphNode[] {
  return wires
    .filter((w) => w.to.node === id && w.to.key === key)
    .map((w) => nodes.find((n) => n.id === w.from.node))
    .filter((n): n is GraphNode => n !== undefined);
}

function getPath(obj: unknown, path: string): unknown {
  let cur: unknown = obj;
  for (const seg of path.split(".")) {
    if (cur === null || typeof cur !== "object") return undefined;
    cur = (cur as Record<string, unknown>)[seg];
  }
  return cur;
}

function substitute(value: string, action: SampleAction): string {
  // In the simulator every sample IS the agent's own transaction, so $agent
  // resolves to the tx's `from` — a `data.from == $agent` rule then holds.
  if (value === "$agent") return action.data.from;
  if (value.startsWith("$")) {
    const resolved = getPath(action, value.slice(1));
    return typeof resolved === "string" ? resolved : value;
  }
  return value;
}

function compare(actual: unknown, op: string, expected: string): boolean {
  if (actual === null || actual === undefined) return false;
  if (op === "eq") return String(actual) === expected;
  if (op === "neq") return String(actual) !== expected;
  const x = parseFloat(String(actual));
  if (op === "between") {
    const [lo, hi] = expected.split(",").map((s) => parseFloat(s));
    return !isNaN(x) && lo !== undefined && hi !== undefined && x >= lo && x <= hi;
  }
  const y = parseFloat(expected);
  if (isNaN(x) || isNaN(y)) return false;
  switch (op) {
    case "lte": return x <= y;
    case "gte": return x >= y;
    case "lt": return x < y;
    case "gt": return x > y;
    default: return false;
  }
}

function evalNode(
  node: GraphNode,
  ctx: { nodes: GraphNode[]; wires: Wire[]; action: SampleAction; lookup: LookupResolver },
  memo: Map<number, Value>,
  seen: Set<number>,
): Value {
  if (memo.has(node.id)) return memo.get(node.id);
  if (seen.has(node.id)) return undefined; // cycle guard
  seen.add(node.id);
  const one = (key: string): Value => {
    const src = inboundNodes(ctx.nodes, ctx.wires, node.id, key)[0];
    return src ? evalNode(src, ctx, memo, seen) : undefined;
  };
  const many = (key: string): Value[] =>
    inboundNodes(ctx.nodes, ctx.wires, node.id, key).map((src) => evalNode(src, ctx, memo, seen));

  const f = node.fields;
  let out: Value;
  switch (node.type) {
    case "transaction": out = ctx.action; break;
    case "routeif": {
      const tx = one("tx");
      const a = tx as SampleAction | undefined;
      out =
        tx !== SKIP && a !== undefined && a !== null &&
        a.contract === f["contract"] && (!f["action"] || a.action === f["action"])
          ? tx
          : SKIP;
      break;
    }
    case "getfield": {
      const src = one("in");
      out = src === undefined || src === null || src === SKIP ? undefined : getPath(src, String(f["path"]));
      break;
    }
    case "constant": out = substitute(String(f["value"]), ctx.action); break;
    case "compare": out = compare(one("a"), String(f["op"]), substitute(String(f["value"]), ctx.action)); break;
    case "inlist": {
      const a = one("a");
      const list = String(f["list"]).split(",").map((s) => substitute(s.trim(), ctx.action)).filter(Boolean);
      const inL = a !== undefined && a !== null && list.includes(String(a));
      out = f["mode"] === "notin" ? !inL : inL;
      break;
    }
    case "contains": {
      const a = one("a");
      out = Array.isArray(a) && a.map(String).includes(substitute(String(f["value"]), ctx.action));
      break;
    }
    case "booland": { const vs = many("in"); out = vs.length > 0 && vs.every((v) => v === true); break; }
    case "boolor": out = many("in").some((v) => v === true); break;
    case "boolnot": out = one("in") !== true; break;
    case "lookup": {
      const tx = one("tx");
      out = tx === undefined || tx === SKIP ? undefined : ctx.lookup(f);
      break;
    }
    case "decision": {
      const tx = one("tx");
      // A rule with no extra predicate (only a Route If) fires on routing
      // alone; a wired condition must be true.
      const hasCond = inboundNodes(ctx.nodes, ctx.wires, node.id, "cond").length > 0;
      const cond = hasCond ? one("cond") : true;
      out = tx !== undefined && tx !== null && tx !== SKIP && cond === true
        ? { effect: f["effect"], rule: node.id }
        : tx === SKIP ? SKIP : null;
      break;
    }
    case "aggregate": out = one("in"); break;
    case "policy": out = many("in"); break;
    default: out = undefined;
  }
  seen.delete(node.id);
  memo.set(node.id, out);
  return out;
}

function reaches(wires: Wire[], fromId: number, toId: number): boolean {
  const stack = [fromId];
  const seen = new Set<number>();
  while (stack.length > 0) {
    const id = stack.pop() as number;
    if (id === toId) return true;
    if (seen.has(id)) continue;
    seen.add(id);
    for (const w of wires) if (w.from.node === id) stack.push(w.to.node);
  }
  return false;
}

function upstream(wires: Wire[], id: number): Set<number> {
  const out = new Set<number>();
  const stack = [id];
  while (stack.length > 0) {
    const x = stack.pop() as number;
    if (out.has(x)) continue;
    out.add(x);
    for (const w of wires) if (w.to.node === x) stack.push(w.from.node);
  }
  return out;
}

/** Human-readable rule label (route target + effect). */
export function ruleLabel(nodes: GraphNode[], wires: Wire[], decision: GraphNode): string {
  const up = [...upstream(wires, decision.id)]
    .map((id) => nodes.find((n) => n.id === id))
    .filter((n): n is GraphNode => n !== undefined);
  const routeif = up.find((n) => n.type === "routeif");
  const base = routeif ? `${routeif.fields["contract"]}::${routeif.fields["action"] || "*"}` : String(decision.fields["effect"]);
  return `${base} → ${String(decision.fields["effect"]).toUpperCase()}`;
}

export { upstream, reaches, inboundNodes, getPath, substitute };

export function evaluateGraph(
  nodes: GraphNode[],
  wires: Wire[],
  actions: SampleAction[],
  lookup: LookupResolver = mockLookup,
): Evaluation {
  const policy = nodes.find((n) => n.type === "policy");
  const decisions = nodes.filter((n) => n.type === "decision");

  // Per-action evaluation (each action independently, issue #28 §Action Evaluation).
  const perAction: PerAction[] = actions.map((action) => {
    const memo = new Map<number, Value>();
    const ctx = { nodes, wires, action, lookup };
    const decs: DecisionResult[] = decisions.map((dn) => {
      const src = inboundNodes(nodes, wires, dn.id, "tx")[0];
      const tx = src ? evalNode(src, ctx, memo, new Set()) : undefined;
      const cond = (() => {
        const c = inboundNodes(nodes, wires, dn.id, "cond")[0];
        return c ? evalNode(c, ctx, memo, new Set()) : undefined;
      })();
      const v = evalNode(dn, ctx, memo, new Set());
      const verdict = v !== null && v !== undefined && v !== SKIP ? ((v as { effect: string }).effect as "allow" | "deny") : null;
      return {
        node: dn,
        routed: tx !== SKIP && tx !== undefined && tx !== null,
        cond,
        verdict,
        reachesPolicy: policy !== undefined && reaches(wires, dn.id, policy.id),
      };
    });
    const reaching = decs.filter((d) => d.reachesPolicy && d.verdict !== null);
    const deny = reaching.find((d) => d.verdict === "deny");
    const allow = reaching.find((d) => d.verdict === "allow");
    const fallback = policy !== undefined && policy.fields["default"] === "allow" ? "allow" : "deny";
    return {
      action,
      decisions: decs,
      verdict: deny ? "deny" : allow ? "allow" : fallback,
      governing: deny ? deny.node : allow ? allow.node : null,
      byDefault: !deny && !allow,
    };
  });

  // Tx-level checks. ALL stages computed (even when an earlier one decides) so
  // the trace always reflects the live graph.
  const maxActions = policy ? parseInt(String(policy.fields["maxActions"]), 10) || 1 : 1;
  const tooMany = actions.length > maxActions;
  const ruleAgg = ruleAggregateCheck(perAction);
  const globalCap = globalCapCheck(nodes, wires, actions, policy);

  let final: "allow" | "deny";
  let decidedBy: DecidedBy;
  let reason: string;
  let governingId: number | null = null;
  let displayIdx = 0;

  const denyIdx = perAction.findIndex((p) => p.verdict === "deny" && p.governing !== null);
  const defIdx = perAction.findIndex((p) => p.verdict === "deny" && p.byDefault);
  const multi = actions.length > 1;

  if (tooMany) {
    final = "deny"; decidedBy = "maxActions";
    reason = `${actions.length} actions > max ${maxActions} per tx → TOO_MANY_ACTIONS (safe default)`;
  } else if (denyIdx >= 0) {
    final = "deny"; decidedBy = "action"; displayIdx = denyIdx;
    const p = perAction[denyIdx] as PerAction;
    governingId = (p.governing as GraphNode).id;
    reason = `${multi ? `action ${denyIdx + 1} ` : ""}denied by “${ruleLabel(nodes, wires, p.governing as GraphNode)}”`;
  } else if (defIdx >= 0) {
    final = "deny"; decidedBy = "action"; displayIdx = defIdx;
    reason = `${multi ? `action ${defIdx + 1} ` : ""}matched no allow rule → default deny`;
  } else if (ruleAgg !== null) {
    final = "deny"; decidedBy = "ruleAgg";
    governingId = ruleAgg.decision.id;
    reason =
      ruleAgg.kind === "cap"
        ? `rule cap: Σ ${ruleAgg.sum?.toFixed(4)} > ${ruleAgg.cap?.toFixed(4)} XPR — auto-aggregated, splitting doesn't bypass`
        : `rate limit: ${ruleAgg.count} to ${ruleAgg.recipient} > ${ruleAgg.limit} per ${ruleAgg.period}`;
  } else if (globalCap !== null) {
    final = "deny"; decidedBy = "globalCap";
    governingId = globalCap.node.id;
    reason = `global cap: Σ ${globalCap.sum.toFixed(4)} > ${globalCap.cap.toFixed(4)} XPR (cross-rule)`;
  } else {
    final = "allow"; decidedBy = "allow";
    const first = perAction[0];
    governingId = first !== undefined && first.governing !== null ? first.governing.id : null;
    reason = multi
      ? `all ${actions.length} actions allowed · limits OK`
      : first !== undefined && first.governing !== null
        ? `allowed by “${ruleLabel(nodes, wires, first.governing)}”`
        : "allowed";
  }

  // Node values + hot path for the deciding action.
  const display = perAction[displayIdx] ?? perAction[0];
  const nodeValues = new Map<number, Value>();
  if (display !== undefined) {
    const ctx = { nodes, wires, action: display.action, lookup };
    for (const n of nodes) evalNode(n, ctx, nodeValues, new Set());
  }
  const hotNodes = new Set<number>();
  const hotWires = new Set<string>();
  if (governingId !== null) {
    const cone = upstream(wires, governingId);
    cone.add(governingId);
    for (const id of cone) hotNodes.add(id);
    if (policy !== undefined) hotNodes.add(policy.id);
    for (const w of wires) {
      if (cone.has(w.from.node) && cone.has(w.to.node)) hotWires.add(wireKey(w));
    }
    // path from the governing decision down to the policy
    if (policy !== undefined) {
      const stack = [governingId];
      const seen = new Set<number>();
      while (stack.length > 0) {
        const id = stack.pop() as number;
        if (seen.has(id)) continue;
        seen.add(id);
        for (const w of wires) {
          if (w.from.node === id && (w.to.node === policy.id || reaches(wires, w.to.node, policy.id))) {
            hotWires.add(wireKey(w));
            hotNodes.add(w.to.node);
            stack.push(w.to.node);
          }
        }
      }
    }
  }

  return { perAction, final, decidedBy, reason, governingId, maxActions, tooMany, ruleAgg, globalCap, nodeValues, hotNodes, hotWires };
}

/** FLOOR 2: per-rule limits auto-aggregated across the tx's actions. */
function ruleAggregateCheck(perAction: PerAction[]): RuleAggHit | null {
  const groups = new Map<number, { decision: GraphNode; actions: SampleAction[] }>();
  for (const p of perAction) {
    if (p.verdict === "allow" && p.governing !== null && p.governing.fields["useLimit"] === true) {
      const g = groups.get(p.governing.id) ?? { decision: p.governing, actions: [] };
      g.actions.push(p.action);
      groups.set(p.governing.id, g);
    }
  }
  for (const g of groups.values()) {
    const f = g.decision.fields;
    const capRaw = String(f["maxPerTx"] ?? "");
    if (capRaw !== "") {
      const cap = parseFloat(capRaw.split(" ")[0] ?? "");
      if (!isNaN(cap)) {
        let sum = 0;
        for (const a of g.actions) {
          const x = parseFloat(a.data.quantity.amount);
          if (!isNaN(x)) sum += x;
        }
        if (sum > cap) return { decision: g.decision, kind: "cap", sum, cap };
      }
    }
    const byRecipient: Record<string, number> = {};
    for (const a of g.actions) {
      const r = a.data.to || "?";
      byRecipient[r] = (byRecipient[r] ?? 0) + 1;
    }
    const rlRaw = String(f["rlCount"] ?? "");
    if (rlRaw !== "" && f["rlPerRecipient"] === true) {
      const limit = parseInt(rlRaw, 10);
      if (!isNaN(limit)) {
        const over = Object.entries(byRecipient).find(([, c]) => c > limit);
        if (over !== undefined) {
          return { decision: g.decision, kind: "rate", recipient: over[0], count: over[1], limit, period: String(f["rlPeriod"]) };
        }
      }
    }
    // A cooldown means a min delay between two actions to the same recipient;
    // two in the SAME tx (delay 0) already violate it.
    const cooldownH = parseFloat(String(f["cooldownH"] ?? ""));
    if (!isNaN(cooldownH) && cooldownH > 0) {
      const repeat = Object.entries(byRecipient).find(([, c]) => c > 1);
      if (repeat !== undefined) {
        return { decision: g.decision, kind: "rate", recipient: repeat[0], count: repeat[1], limit: 1, period: `${cooldownH}h cooldown` };
      }
    }
  }
  return null;
}

/** CEILING: the optional cross-rule Global cap node. */
function globalCapCheck(
  nodes: GraphNode[],
  wires: Wire[],
  actions: SampleAction[],
  policy: GraphNode | undefined,
): GlobalCapHit | null {
  if (policy === undefined) return null;
  for (const node of nodes.filter((n) => n.type === "aggregate")) {
    if (!reaches(wires, node.id, policy.id)) continue;
    let sum = 0;
    for (const a of actions) {
      if (a.action === "transfer") {
        const x = parseFloat(a.data.quantity.amount);
        if (!isNaN(x)) sum += x;
      }
    }
    const cap = parseFloat(String(node.fields["maxTotal"] ?? "").split(" ")[0] ?? "");
    if (!isNaN(cap) && sum > cap) return { node, sum, cap };
  }
  return null;
}
