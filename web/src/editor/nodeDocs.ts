/**
 * Human docs for each node type — the content behind the `?` help modal.
 * Structural port info (side/key/label/type) comes from SPECS; this only adds
 * the prose: a category, a one-line purpose, per-port and per-field
 * descriptions, and the gotcha note. `portDesc` is keyed by the port key.
 */

import type { NodeType } from "./types";

export interface FieldDoc {
  name: string;
  range: string;
  desc: string;
}

export interface NodeDoc {
  cat: string;
  subtitle: string;
  portDesc: Record<string, string>;
  fields: FieldDoc[];
  notes?: string;
}

export const NODE_DOCS: Record<NodeType, NodeDoc> = {
  transaction: {
    cat: "flow",
    subtitle:
      "The raw transaction the agent submits — one or more Antelope actions. It flows in on the left and is routed to the rule sets that match.",
    portDesc: {
      tx: "The action(s) to evaluate. Always raw, unserialized JSON — never a packed transaction.",
    },
    fields: [],
    notes:
      "This is the only thing the agent controls. SignBox decides whether to sign it; the agent never touches a key.",
  },
  routeif: {
    cat: "route",
    subtitle:
      "Routes a transaction into this rule set only when it matches a contract and action. A non-match simply skips this branch — it does not deny.",
    portDesc: {
      tx: "The incoming action from the Transaction (or another routing stage).",
      out: "The action, forwarded only if it matched; otherwise the branch is skipped (SKIP).",
    },
    fields: [
      { name: "contract", range: "account", desc: "The contract to match, e.g. eosio.token, xtokens, atomicmarket." },
      { name: "action", range: "name · empty = any", desc: "The action name, e.g. transfer. Leave empty to match any action on the contract." },
    ],
    notes: "Routing is not a verdict. If nothing routes to a Decision, the Global Policy default (usually deny) applies.",
  },
  getfield: {
    cat: "data",
    subtitle: "Extracts one field from an object by path — a routed action, or a Lookup row.",
    portDesc: {
      in: "An object to read from: the routed tx, or a Lookup row (this input accepts both tx and val).",
      out: "The value at the path — a scalar, or an array (feed that to Contains).",
    },
    fields: [
      {
        name: "field path",
        range: "custom",
        desc: "e.g. data.to, data.quantity.amount, or a bare row field like producers. Array indices use dots (data.0.x), never brackets. Validated against the daemon's vocabulary at compile time.",
      },
    ],
    notes: "On a Lookup row the row is already unwrapped — use the bare field name (producers), not data[0].producers.",
  },
  constant: {
    cat: "data",
    subtitle: "A fixed value to compare against, without needing a Get Field.",
    portDesc: { out: "The literal value." },
    fields: [
      {
        name: "value",
        range: "literal · $data.to · $agent",
        desc: "A constant, or a substitution resolved against the action ($data.to = the recipient, $agent = the signer).",
      },
    ],
    notes: "Substitutions ($…) are resolved at evaluation time against the incoming action.",
  },
  lookup: {
    cat: "data",
    subtitle:
      "Reads a single on-chain table row and hands it downstream. The one deterministic provider the daemon enforces: xpr.rpc.tableRow.",
    portDesc: {
      tx: "The routed action — used to resolve the key ($data.to, $agent…).",
      out: "The matched row object, or nothing if the row doesn't exist / can't be read (fail-closed).",
    },
    fields: [
      { name: "source", range: "table · http", desc: "table = xpr.rpc.tableRow, ENFORCED on-chain. http = generic GET, TEST-ONLY (never in the pushed policy)." },
      { name: "contract", range: "account", desc: "The contract owning the table, e.g. eosio." },
      { name: "table", range: "name", desc: "The table to read, e.g. voters." },
      { name: "key", range: "$data.to · $agent · literal", desc: "The primary key of the row. Bounded on this key with limit 1 — you get the row directly (no rows[0])." },
    ],
    notes:
      "Deterministic by design (INV-008-A): unreachable / timeout / malformed ⇒ the rule refuses. Providers only NARROW a rule, never widen it.",
  },
  compare: {
    cat: "compare",
    subtitle: "True when a value satisfies a bounded comparison.",
    portDesc: {
      a: "The value to test — usually from a Get Field.",
      out: "true if the comparison holds.",
    },
    fields: [
      { name: "op", range: "eq · lte · gte", desc: "The comparison. Only bounded ops compile to a policy." },
      { name: "value", range: "literal", desc: "The bound to compare against." },
    ],
    notes:
      "Amounts must match the token's precision — comparing 1.0000 to 1.000000 fails closed (the daemon refusing an ambiguous compare).",
  },
  inlist: {
    cat: "compare",
    subtitle: "Membership (or exclusion) against a fixed list.",
    portDesc: {
      a: "The value to test — usually a Get Field (data.to).",
      out: "true if the value is in (or, for notin, out of) the list.",
    },
    fields: [
      { name: "mode", range: "in · notin", desc: "in = whitelist, notin = blacklist." },
      { name: "list", range: "comma-separated", desc: "e.g. alice, bob, carol. Supports $data substitutions." },
    ],
    notes: "For a single recipient this is cleaner than Compare (eq).",
  },
  contains: {
    cat: "compare",
    subtitle: "True when an ARRAY contains a given value — e.g. a whitelist row's array includes the recipient.",
    portDesc: {
      a: "The array to search — typically a Lookup row field via Get Field. A scalar input can never match.",
      out: "true if the array contains the value, else false.",
    },
    fields: [
      { name: "value", range: "literal · $data.to", desc: "The element to look for. Supports substitutions like $data.to." },
    ],
    notes: "Compiles to the tableRow provider's `contains` op. For a scalar equality use Compare (eq) or In List instead.",
  },
  booland: {
    cat: "boolean",
    subtitle: "True only when every wired condition is true.",
    portDesc: { in: "One or more conditions (multi-input).", out: "true when all inputs are true." },
    fields: [],
    notes: "A rule's conditions are an implicit AND already — this node is for combining explicit branches into one.",
  },
  boolor: {
    cat: "boolean",
    subtitle: "True when any wired condition is true.",
    portDesc: { in: "One or more conditions (multi-input).", out: "true when at least one input is true." },
    fields: [],
    notes: "OR has no single declarative form — the compiler asks you to split it into separate rules (each is OR-ed by the policy).",
  },
  boolnot: {
    cat: "boolean",
    subtitle: "Inverts a condition.",
    portDesc: { in: "The condition to invert.", out: "true when the input is false." },
    fields: [],
    notes: "Often clearer as a `not in` list or the opposite Compare op.",
  },
  decision: {
    cat: "decision",
    subtitle: "Turns a routed transaction into a verdict — allow or deny — with optional, auto-aggregated limits.",
    portDesc: {
      tx: "The routed action from a Route If. Present = this rule applies to that action.",
      cond: "Must be true for the verdict to fire. No wire = fires on routing alone.",
      out: "allow / deny, wired into the Global Policy.",
    },
    fields: [
      { name: "effect", range: "allow · deny", desc: "The verdict this rule produces when it fires." },
      { name: "max per transaction", range: "asset · Σ actions", desc: "Cap on the total moved by this rule's matching actions in one tx." },
      { name: "rate limit", range: "count / period", desc: "Max matching actions per hour/day, optionally per recipient." },
      { name: "cooldown", range: "hours / recipient", desc: "Minimum delay between payments to the same recipient." },
    ],
    notes:
      "Limits are the FLOOR of the two-tier safety model: they auto-aggregate across every action in the tx — no extra node needed. A refusal is the system working.",
  },
  aggregate: {
    cat: "decision",
    subtitle: "An opt-in CEILING across all rules — the second tier of the safety model.",
    portDesc: {
      in: "Verdicts from the Decisions (multi-input).",
      out: "The same verdicts, refused if the cross-rule total is exceeded.",
    },
    fields: [
      { name: "max total / tx", range: "asset · all rules", desc: "Cap on the sum moved by every allowing rule in one transaction." },
    ],
    notes: "Advanced. The per-rule limits (the floor) already protect each rule; this caps cross-rule totals.",
  },
  policy: {
    cat: "flow",
    subtitle: "The root the graph compiles down to — the bounded, hashable document the daemon actually evaluates.",
    portDesc: { in: "Every Decision's verdict wires in here (multi-input)." },
    fields: [
      { name: "max actions / tx", range: "integer · default 1", desc: "The absolute floor: multi-action transactions are refused unless you raise this." },
      { name: "default", range: "deny · allow", desc: "What happens when nothing matched. Keep it deny (fail-closed)." },
    ],
    notes:
      "The graph is only the authoring surface. It compiles to this policy + a policyhash; nothing without a bounded declarative form is ever emitted.",
  },
};
