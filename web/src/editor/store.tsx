/**
 * Graph state: nodes, wires, selection, sample tx, pan/zoom view — a single
 * reducer so every mutation is explicit and testable. Wire insertion enforces
 * the typed-port rules (same type only, single-input except AND/OR/Policy).
 */

import { createContext, useContext, useReducer, type Dispatch, type ReactNode } from "react";
import type { Fields, GraphNode, NodeType, Wire } from "./types";
import { SPECS, isMultiInput } from "./nodeSpecs";

export interface ViewTransform {
  x: number;
  y: number;
  z: number;
}

export interface GraphState {
  nodes: GraphNode[];
  wires: Wire[];
  selected: number | null;
  view: ViewTransform;
  nextId: number;
  /** Bumped when a batch of nodes is added so the canvas re-frames the graph. */
  fitNonce: number;
}

export type GraphAction =
  | { type: "add-node"; nodeType: NodeType; x: number; y: number }
  | { type: "move-node"; id: number; x: number; y: number }
  | { type: "delete-node"; id: number }
  | { type: "set-field"; id: number; key: string; value: string | boolean }
  | { type: "add-wire"; from: { node: number; key: string }; to: { node: number; key: string } }
  | { type: "delete-wire"; wire: Wire }
  | { type: "add-scaffold"; nodes: GraphNode[]; wires: Wire[]; nextId: number }
  | { type: "select"; id: number | null }
  | { type: "set-view"; view: ViewTransform }
  | { type: "reset-demo" };

function addNode(state: GraphState, nodeType: NodeType, x: number, y: number): GraphState {
  const spec = SPECS[nodeType];
  if (spec.single === true && state.nodes.some((n) => n.type === nodeType)) {
    const existing = state.nodes.find((n) => n.type === nodeType) as GraphNode;
    return { ...state, selected: existing.id };
  }
  const node: GraphNode = { id: state.nextId, type: nodeType, x, y, fields: spec.defaults() };
  return { ...state, nodes: [...state.nodes, node], selected: node.id, nextId: state.nextId + 1 };
}

function addWire(state: GraphState, from: { node: number; key: string }, to: { node: number; key: string }): GraphState {
  const fromNode = state.nodes.find((n) => n.id === from.node);
  const toNode = state.nodes.find((n) => n.id === to.node);
  if (fromNode === undefined || toNode === undefined || from.node === to.node) return state;
  const outPort = SPECS[fromNode.type].ports.find((p) => p.side === "out" && p.key === from.key);
  const inPort = SPECS[toNode.type].ports.find((p) => p.side === "in" && p.key === to.key);
  if (outPort === undefined || inPort === undefined || outPort.type !== inPort.type) return state;
  let wires = state.wires;
  if (!isMultiInput(toNode.type, to.key)) {
    wires = wires.filter((w) => !(w.to.node === to.node && w.to.key === to.key));
  }
  if (wires.some((w) => w.from.node === from.node && w.from.key === from.key && w.to.node === to.node && w.to.key === to.key)) {
    return { ...state, wires };
  }
  return { ...state, wires: [...wires, { from, to }] };
}

function reducer(state: GraphState, action: GraphAction): GraphState {
  switch (action.type) {
    case "add-node":
      return addNode(state, action.nodeType, action.x, action.y);
    case "move-node":
      return {
        ...state,
        nodes: state.nodes.map((n) => (n.id === action.id ? { ...n, x: action.x, y: action.y } : n)),
      };
    case "delete-node": {
      const node = state.nodes.find((n) => n.id === action.id);
      if (node === undefined || SPECS[node.type].single === true) return state;
      return {
        ...state,
        nodes: state.nodes.filter((n) => n.id !== action.id),
        wires: state.wires.filter((w) => w.from.node !== action.id && w.to.node !== action.id),
        selected: state.selected === action.id ? null : state.selected,
      };
    }
    case "set-field":
      return {
        ...state,
        nodes: state.nodes.map((n) =>
          n.id === action.id ? { ...n, fields: { ...n.fields, [action.key]: action.value } } : n,
        ),
      };
    case "add-wire":
      return addWire(state, action.from, action.to);
    case "delete-wire": {
      const w = action.wire;
      return {
        ...state,
        wires: state.wires.filter(
          (x) =>
            !(
              x.from.node === w.from.node &&
              x.from.key === w.from.key &&
              x.to.node === w.to.node &&
              x.to.key === w.to.key
            ),
        ),
      };
    }
    case "add-scaffold":
      if (action.nodes.length === 0) return state;
      return {
        ...state,
        nodes: [...state.nodes, ...action.nodes],
        wires: [...state.wires, ...action.wires],
        nextId: action.nextId,
        selected: action.nodes[0]?.id ?? state.selected,
        fitNonce: state.fitNonce + 1,
      };
    case "select":
      return { ...state, selected: action.id };
    case "set-view":
      return { ...state, view: action.view };
    case "reset-demo":
      return demoState();
    default:
      return state;
  }
}

/** The two-rule-set demo graph (whitelisted transfer + deny xUSDC). */
export function demoState(): GraphState {
  let id = 1;
  const mk = (type: NodeType, x: number, y: number, fields?: Fields): GraphNode => ({
    id: id++,
    type,
    x,
    y,
    fields: { ...SPECS[type].defaults(), ...(fields ?? {}) },
  });
  const txn = mk("transaction", 30, 300);
  const riA = mk("routeif", 250, 120);
  const gfAmt = mk("getfield", 250, 300, { path: "data.quantity.amount" });
  const cmpAmt = mk("compare", 470, 300, { op: "lte", value: "1.0000" });
  const look = mk("lookup", 250, 470);
  const gfList = mk("getfield", 470, 470, { path: "allowed" });
  const cont = mk("contains", 670, 470, { value: "$data.to" });
  const and = mk("booland", 860, 380);
  const decA = mk("decision", 1050, 240, {
    effect: "allow",
    useLimit: true,
    maxPerTx: "1.0000 XPR",
    rlCount: "1",
    rlPeriod: "day",
    rlPerRecipient: true,
  });
  const riB = mk("routeif", 250, 650, { contract: "xtokens", action: "transfer" });
  const gfSym = mk("getfield", 470, 650, { path: "data.quantity.symbol" });
  const cmpSym = mk("compare", 670, 650, { op: "eq", value: "XUSDC" });
  const decB = mk("decision", 1050, 640, { effect: "deny" });
  const pol = mk("policy", 1320, 400, { default: "deny", maxActions: "1" });
  const W = (fromNode: GraphNode, fromKey: string, toNode: GraphNode, toKey: string): Wire => ({
    from: { node: fromNode.id, key: fromKey },
    to: { node: toNode.id, key: toKey },
  });
  return {
    nodes: [txn, riA, gfAmt, cmpAmt, look, gfList, cont, and, decA, riB, gfSym, cmpSym, decB, pol],
    wires: [
      W(txn, "tx", riA, "tx"),
      W(txn, "tx", look, "tx"),
      W(txn, "tx", riB, "tx"),
      W(riA, "out", gfAmt, "in"),
      W(gfAmt, "out", cmpAmt, "a"),
      W(cmpAmt, "out", and, "in"),
      W(look, "out", gfList, "in"),
      W(gfList, "out", cont, "a"),
      W(cont, "out", and, "in"),
      W(and, "out", decA, "cond"),
      W(riA, "out", decA, "tx"),
      W(decA, "out", pol, "in"),
      W(riB, "out", gfSym, "in"),
      W(gfSym, "out", cmpSym, "a"),
      W(cmpSym, "out", decB, "cond"),
      W(riB, "out", decB, "tx"),
      W(decB, "out", pol, "in"),
    ],
    selected: txn.id,
    view: { x: 0, y: 0, z: 1 },
    nextId: id,
    fitNonce: 0,
  };
}

const GraphContext = createContext<{ state: GraphState; dispatch: Dispatch<GraphAction> } | null>(null);

export function GraphProvider({ initial, children }: { initial?: GraphState; children: ReactNode }) {
  const [state, dispatch] = useReducer(reducer, initial ?? undefined, (arg) => arg ?? demoState());
  return <GraphContext.Provider value={{ state, dispatch }}>{children}</GraphContext.Provider>;
}

export function useGraph() {
  const ctx = useContext(GraphContext);
  if (ctx === null) throw new Error("useGraph must be used inside <GraphProvider>");
  return ctx;
}
