/**
 * Wire layer — pure SVG inside the world transform. Positions derive from
 * state (deterministic port offsets), so there is no DOM measurement at all.
 */

import type { GraphNode, Wire } from "./types";
import { portPosition } from "./types";
import { SPECS, portIndex, nodeColor } from "./nodeSpecs";
import { wireKey } from "./eval";

const TYPE_COLOR: Record<string, string> = {
  tx: "var(--tx)",
  val: "var(--val)",
  bool: "var(--bool)",
  verdict: "var(--verdict)",
};

function bezier(a: { x: number; y: number }, b: { x: number; y: number }): string {
  const dx = Math.max(38, Math.abs(b.x - a.x) * 0.5);
  return `M${a.x},${a.y} C${a.x + dx},${a.y} ${b.x - dx},${b.y} ${b.x},${b.y}`;
}

export interface TempWire {
  a: { x: number; y: number };
  b: { x: number; y: number };
}

export function Wires({
  nodes,
  wires,
  hotWires,
  hotColor,
  temp,
}: {
  nodes: GraphNode[];
  wires: Wire[];
  hotWires: Set<string>;
  hotColor: string;
  temp: TempWire | null;
}) {
  const byId = new Map(nodes.map((n) => [n.id, n]));
  const anyHot = hotWires.size > 0;
  return (
    <svg className="wires">
      {wires.map((w) => {
        const fromNode = byId.get(w.from.node);
        const toNode = byId.get(w.to.node);
        if (fromNode === undefined || toNode === undefined) return null;
        const fi = portIndex(fromNode.type, w.from.key, "out");
        const ti = portIndex(toNode.type, w.to.key, "in");
        if (fi < 0 || ti < 0) return null;
        const a = portPosition(fromNode, fi, "out");
        const b = portPosition(toNode, ti, "in");
        const key = wireKey(w);
        const hot = hotWires.has(key);
        const spec = SPECS[fromNode.type].ports[fi];
        const baseColor =
          fromNode.type === "decision" ? nodeColor(fromNode.type, fromNode.fields) : TYPE_COLOR[spec?.type ?? "val"];
        return (
          <path
            key={key}
            d={bezier(a, b)}
            fill="none"
            className={hot ? "hotwire" : undefined}
            stroke={hot ? hotColor : baseColor}
            strokeWidth={hot ? 3.2 : 2}
            opacity={hot ? 1 : anyHot ? 0.3 : 0.8}
          />
        );
      })}
      {temp !== null && (
        <path d={bezier(temp.a, temp.b)} fill="none" stroke="var(--accent)" strokeWidth={2.4} strokeDasharray="5 4" />
      )}
    </svg>
  );
}
