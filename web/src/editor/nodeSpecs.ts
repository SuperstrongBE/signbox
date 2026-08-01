/**
 * The node registry: per type → title, category color, typed ports, default
 * fields. The node set mirrors the issue #28 model with the two-tier safety
 * decisions baked in (Decision carries auto-aggregated limits; Global cap is
 * an explicit opt-in ceiling; Policy carries the maxActions floor).
 */

import type { Fields, NodeType, PortSpec } from "./types";

export interface NodeSpec {
  title: string;
  /** CSS color token (var(--…)) for the node category. */
  color: string;
  ports: PortSpec[];
  /** Only one instance allowed (Transaction, Policy). */
  single?: boolean;
  defaults: () => Fields;
}

export const SPECS: Record<NodeType, NodeSpec> = {
  transaction: {
    title: "Incoming transaction",
    color: "var(--tx)",
    single: true,
    ports: [{ side: "out", key: "tx", label: "action →", type: "tx" }],
    defaults: () => ({}),
  },
  routeif: {
    title: "Route If",
    color: "var(--tx)",
    ports: [
      { side: "in", key: "tx", label: "tx", type: "tx" },
      { side: "out", key: "out", label: "→ matched", type: "tx" },
    ],
    defaults: () => ({ contract: "eosio.token", action: "transfer" }),
  },
  getfield: {
    title: "Get Field",
    color: "var(--val)",
    ports: [
      { side: "in", key: "in", label: "data", type: "val" },
      { side: "out", key: "out", label: "→ value", type: "val" },
    ],
    defaults: () => ({ path: "data.quantity.amount" }),
  },
  constant: {
    title: "Constant",
    color: "var(--val)",
    ports: [{ side: "out", key: "out", label: "→ value", type: "val" }],
    defaults: () => ({ value: "1.0000" }),
  },
  compare: {
    title: "Compare",
    color: "var(--val)",
    ports: [
      { side: "in", key: "a", label: "value", type: "val" },
      { side: "out", key: "out", label: "→ bool", type: "bool" },
    ],
    defaults: () => ({ op: "lte", value: "1.0000" }),
  },
  inlist: {
    title: "In List",
    color: "var(--val)",
    ports: [
      { side: "in", key: "a", label: "value", type: "val" },
      { side: "out", key: "out", label: "→ bool", type: "bool" },
    ],
    defaults: () => ({ mode: "in", list: "alice, bob" }),
  },
  contains: {
    title: "Contains",
    color: "var(--val)",
    ports: [
      { side: "in", key: "a", label: "array", type: "val" },
      { side: "out", key: "out", label: "→ bool", type: "bool" },
    ],
    defaults: () => ({ value: "$data.to" }),
  },
  booland: {
    title: "AND",
    color: "var(--bool)",
    ports: [
      { side: "in", key: "in", label: "bool", type: "bool" },
      { side: "out", key: "out", label: "→ bool", type: "bool" },
    ],
    defaults: () => ({}),
  },
  boolor: {
    title: "OR",
    color: "var(--bool)",
    ports: [
      { side: "in", key: "in", label: "bool", type: "bool" },
      { side: "out", key: "out", label: "→ bool", type: "bool" },
    ],
    defaults: () => ({}),
  },
  boolnot: {
    title: "NOT",
    color: "var(--bool)",
    ports: [
      { side: "in", key: "in", label: "bool", type: "bool" },
      { side: "out", key: "out", label: "→ bool", type: "bool" },
    ],
    defaults: () => ({}),
  },
  lookup: {
    title: "Lookup",
    color: "var(--lookup)",
    ports: [
      { side: "in", key: "tx", label: "tx", type: "tx" },
      { side: "out", key: "out", label: "→ json", type: "val" },
    ],
    defaults: () => ({ provider: "xpr.rpc.tableRow", contract: "whitelister", table: "lists", key: "$agent" }),
  },
  decision: {
    title: "Decision",
    color: "var(--allow)",
    ports: [
      { side: "in", key: "tx", label: "routed", type: "tx" },
      { side: "in", key: "cond", label: "condition", type: "bool" },
      { side: "out", key: "out", label: "→ verdict", type: "verdict" },
    ],
    defaults: () => ({
      effect: "allow",
      useLimit: false,
      maxPerTx: "1.0000 XPR",
      rlCount: "",
      rlPeriod: "day",
      rlPerRecipient: true,
      cooldownH: "",
    }),
  },
  aggregate: {
    title: "Global cap",
    color: "var(--bool)",
    ports: [
      { side: "in", key: "in", label: "verdict", type: "verdict" },
      { side: "out", key: "out", label: "→ verdict", type: "verdict" },
    ],
    defaults: () => ({ maxTotal: "10.0000 XPR" }),
  },
  policy: {
    title: "Global Policy",
    color: "var(--neutral)",
    single: true,
    ports: [{ side: "in", key: "in", label: "verdicts", type: "verdict" }],
    defaults: () => ({ default: "deny", maxActions: "1" }),
  },
};

/** Input ports that accept MULTIPLE wires (everything else is single-input). */
export function isMultiInput(type: NodeType, key: string): boolean {
  return (type === "booland" || type === "boolor" || type === "policy") && (key === "in");
}

/**
 * Whether an out-port may connect to a given in-port. Types must match, with
 * one exception: Get Field extracts a path from any object, so its `in` accepts
 * a routed transaction (`tx`) as well as a lookup's json value (`val`).
 */
export function portsCompatible(fromType: string, toNode: NodeType, toKey: string, toType: string): boolean {
  if (fromType === toType) return true;
  if (toNode === "getfield" && toKey === "in" && fromType === "tx" && toType === "val") return true;
  return false;
}

export function portIndex(type: NodeType, key: string, side: "in" | "out"): number {
  return SPECS[type].ports.findIndex((p) => p.key === key && p.side === side);
}

/** The color of a node instance (Decision follows its effect). */
export function nodeColor(type: NodeType, fields: Record<string, string | boolean>): string {
  if (type === "decision") return fields["effect"] === "deny" ? "var(--deny)" : "var(--allow)";
  return SPECS[type].color;
}
