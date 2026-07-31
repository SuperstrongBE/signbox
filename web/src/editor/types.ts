/**
 * Editor domain types. All geometry is in WORLD coordinates (the pan/zoom
 * transform lives on a single layer), so wire positions derive purely from
 * state — no DOM measurement anywhere.
 */

export type PortType = "tx" | "val" | "bool" | "verdict";
export type PortSide = "in" | "out";

export interface PortSpec {
  side: PortSide;
  key: string;
  label: string;
  type: PortType;
}

export type NodeType =
  | "transaction"
  | "routeif"
  | "getfield"
  | "constant"
  | "compare"
  | "inlist"
  | "contains"
  | "booland"
  | "boolor"
  | "boolnot"
  | "lookup"
  | "decision"
  | "aggregate"
  | "policy";

/** Node field values are all strings/booleans — simple controlled inputs. */
export type Fields = Record<string, string | boolean>;

export interface GraphNode {
  id: number;
  type: NodeType;
  x: number;
  y: number;
  fields: Fields;
}

export interface PortRef {
  node: number;
  key: string;
}

export interface Wire {
  from: PortRef; // always an "out" port
  to: PortRef; // always an "in" port
}

export interface SampleAction {
  contract: string;
  action: string;
  data: { from: string; to: string; quantity: { amount: string; symbol: string } };
}

export interface Sample {
  label: string;
  actions: SampleAction[];
}

/** Fixed node geometry (used for ports and fit-view). */
export const NODE_W = 210;
export const PORT_TOP = 44;
export const PORT_GAP = 20;

/** World-space center of a port, derived from state only. */
export function portPosition(node: GraphNode, portIndex: number, side: PortSide): { x: number; y: number } {
  return {
    x: side === "out" ? node.x + NODE_W : node.x,
    y: node.y + PORT_TOP + portIndex * PORT_GAP + 6,
  };
}
