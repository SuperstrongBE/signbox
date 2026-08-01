/**
 * "Convert to route": turn a concrete example transaction into the policy
 * branch that governs it. For each distinct contract::action we drop a
 * pre-filled Route If, a Get Field stub per data field, and an (allow)
 * Decision — all wired Transaction → Route If → Decision → Policy, so you
 * only have to add the conditions. Pairs that already have a Route If are
 * skipped so converting the same tx twice doesn't duplicate branches.
 */

import type { Fields, GraphNode, Wire } from "./types";
import type { GraphState } from "./store";
import { SPECS } from "./nodeSpecs";
import { txToRoutes } from "./testTx";

export interface Scaffold {
  nodes: GraphNode[];
  wires: Wire[];
  nextId: number;
}

const ROUTE_X = 250;
const FIELD_X = 480;
const DEC_X = 760;

export function buildScaffold(state: GraphState, tx: unknown): Scaffold {
  const existing = new Set(
    state.nodes
      .filter((n) => n.type === "routeif")
      .map((n) => `${String(n.fields["contract"])}::${String(n.fields["action"])}`),
  );
  const fresh = txToRoutes(tx).filter((r) => !existing.has(`${r.contract}::${r.action}`));

  const txNode = state.nodes.find((n) => n.type === "transaction");
  const polNode = state.nodes.find((n) => n.type === "policy");
  const nodes: GraphNode[] = [];
  const wires: Wire[] = [];
  let id = state.nextId;
  // Lay the new branches below whatever is already on the canvas.
  let branchY = state.nodes.reduce((m, n) => Math.max(m, n.y), 0) + 170;

  for (const r of fresh) {
    const rif = mk(id++, "routeif", ROUTE_X, branchY, { contract: r.contract, action: r.action });
    nodes.push(rif);
    if (txNode !== undefined) wires.push(wire(txNode.id, "tx", rif.id, "tx"));

    r.paths.forEach((path, j) => {
      const gf = mk(id++, "getfield", FIELD_X, branchY + j * 78, { path });
      nodes.push(gf);
      wires.push(wire(rif.id, "out", gf.id, "in"));
    });

    const dec = mk(id++, "decision", DEC_X, branchY, { effect: "allow" });
    nodes.push(dec);
    wires.push(wire(rif.id, "out", dec.id, "tx"));
    if (polNode !== undefined) wires.push(wire(dec.id, "out", polNode.id, "in"));

    branchY += Math.max(150, r.paths.length * 78 + 70);
  }

  return { nodes, wires, nextId: id };
}

function mk(id: number, type: GraphNode["type"], x: number, y: number, fields: Fields): GraphNode {
  return { id, type, x, y, fields: { ...SPECS[type].defaults(), ...fields } };
}

function wire(fromNode: number, fromKey: string, toNode: number, toKey: string): Wire {
  return { from: { node: fromNode, key: fromKey }, to: { node: toNode, key: toKey } };
}
