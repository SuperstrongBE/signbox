/**
 * One node: chrome (header, badge, delete), typed ports at deterministic
 * offsets, and the per-type body. Memo'd so dragging one node never re-renders
 * the others.
 */

import { memo, type PointerEvent } from "react";
import type { GraphNode as NodeModel } from "./types";
import { PORT_TOP, PORT_GAP } from "./types";
import { SPECS, nodeColor } from "./nodeSpecs";
import { NodeBody } from "./nodeBodies";
import { useGraph } from "./store";
import { useHelp } from "./help";

const TYPE_COLOR: Record<string, string> = {
  tx: "var(--tx)",
  val: "var(--val)",
  bool: "var(--bool)",
  verdict: "var(--verdict)",
};

export interface GraphNodeProps {
  node: NodeModel;
  selected: boolean;
  hot: boolean;
  hotColor: string;
  skipDim: boolean;
  badge: string;
  onHeaderPointerDown: (e: PointerEvent, node: NodeModel) => void;
  onPortPointerDown: (e: PointerEvent, node: NodeModel, key: string, side: "in" | "out", type: string) => void;
}

export const GraphNodeView = memo(function GraphNodeView({
  node,
  selected,
  hot,
  hotColor,
  skipDim,
  badge,
  onHeaderPointerDown,
  onPortPointerDown,
}: GraphNodeProps) {
  const { dispatch } = useGraph();
  const { open: openHelp } = useHelp();
  const spec = SPECS[node.type];
  const color = nodeColor(node.type, node.fields);
  const title = node.type === "decision" ? `Decision · ${String(node.fields["effect"])}` : spec.title;
  return (
    <div
      className={`gnode ${selected ? "sel" : ""} ${hot ? "hot" : ""} ${skipDim ? "skipdim" : ""}`}
      style={{
        left: node.x,
        top: node.y,
        ["--c" as string]: color,
        ["--hc" as string]: hotColor,
      }}
      onPointerDown={() => dispatch({ type: "select", id: node.id })}
    >
      <div className="hd" onPointerDown={(e) => onHeaderPointerDown(e, node)}>
        <span className="sw" />
        <span className="ttl">{title}</span>
        {badge !== "" && <span className="bdg">{badge}</span>}
        <button
          className="qh"
          aria-label={`Help for ${spec.title}`}
          title="What is this node?"
          onClick={(e) => {
            e.stopPropagation();
            openHelp(node.type);
          }}
          onPointerDown={(e) => e.stopPropagation()}
        >
          ?
        </button>
        {spec.single !== true && (
          <button
            className="x"
            aria-label="delete node"
            onClick={(e) => {
              e.stopPropagation();
              dispatch({ type: "delete-node", id: node.id });
            }}
            onPointerDown={(e) => e.stopPropagation()}
          >
            ×
          </button>
        )}
      </div>
      <div className="body">
        <NodeBody node={node} />
      </div>
      {spec.ports.map((p, i) => {
        const top = PORT_TOP + i * PORT_GAP;
        const portColor = node.type === "decision" && p.side === "out" ? color : TYPE_COLOR[p.type];
        return (
          <span key={`${p.side}:${p.key}`}>
            <span
              className={`gport ${p.side}`}
              style={{ top, ["--pc" as string]: portColor }}
              data-port-node={node.id}
              data-port-key={p.key}
              data-port-side={p.side}
              data-port-type={p.type}
              onPointerDown={(e) => {
                e.stopPropagation();
                onPortPointerDown(e, node, p.key, p.side, p.type);
              }}
            />
            <span
              className="gportlbl"
              style={p.side === "out" ? { top: top - 1, right: 16 } : { top: top - 1, left: 16 }}
            >
              {p.label}
            </span>
          </span>
        );
      })}
    </div>
  );
});
