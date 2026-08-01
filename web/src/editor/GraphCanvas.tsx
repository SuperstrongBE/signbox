/**
 * The canvas: pan/zoom world, draggable nodes, port-to-port wiring, palette
 * drag-and-drop. Transient gestures (drag, wiring, temp wire) live in refs and
 * local state; only committed changes hit the reducer.
 */

import { useEffect, useRef, useState, type PointerEvent as ReactPointerEvent } from "react";
import type { GraphNode as NodeModel, NodeType } from "./types";
import { NODE_W, portPosition } from "./types";
import { portIndex } from "./nodeSpecs";
import { useGraph, type ViewTransform } from "./store";
import { GraphNodeView } from "./GraphNode";
import { Wires, type TempWire } from "./Wires";
import { SKIP, type Evaluation } from "./eval";

function formatBadge(value: unknown): string {
  if (value === SKIP) return "skip";
  if (value === undefined || value === null) return "";
  if (value === true) return "✓";
  if (value === false) return "✗";
  if (Array.isArray(value)) return "[…]";
  if (typeof value === "object") {
    const effect = (value as { effect?: unknown }).effect;
    return typeof effect === "string" ? effect : "{…}";
  }
  return String(value).slice(0, 10);
}

export function GraphCanvas({ evaluation }: { evaluation: Evaluation }) {
  const { state, dispatch } = useGraph();
  const wrapRef = useRef<HTMLDivElement>(null);
  const [temp, setTemp] = useState<TempWire | null>(null);
  const [panning, setPanning] = useState(false);
  const [dropOk, setDropOk] = useState(false);

  const viewRef = useRef<ViewTransform>(state.view);
  viewRef.current = state.view;

  function screenToWorld(clientX: number, clientY: number): { x: number; y: number } {
    const rect = wrapRef.current?.getBoundingClientRect();
    const v = viewRef.current;
    const left = rect?.left ?? 0;
    const top = rect?.top ?? 0;
    return { x: (clientX - left - v.x) / v.z, y: (clientY - top - v.y) / v.z };
  }

  function zoomAt(clientX: number, clientY: number, factor: number) {
    const rect = wrapRef.current?.getBoundingClientRect();
    const cx = clientX - (rect?.left ?? 0);
    const cy = clientY - (rect?.top ?? 0);
    const v = viewRef.current;
    const wx = (cx - v.x) / v.z;
    const wy = (cy - v.y) / v.z;
    const z = Math.min(2, Math.max(0.35, v.z * factor));
    dispatch({ type: "set-view", view: { x: cx - wx * z, y: cy - wy * z, z } });
  }

  function fitView() {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (rect === undefined || state.nodes.length === 0 || rect.width < 10) return;
    let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
    for (const n of state.nodes) {
      minX = Math.min(minX, n.x);
      minY = Math.min(minY, n.y);
      maxX = Math.max(maxX, n.x + NODE_W);
      maxY = Math.max(maxY, n.y + 240);
    }
    const pad = 44;
    const z = Math.min(1.25, Math.max(0.3, Math.min((rect.width - pad * 2) / (maxX - minX), (rect.height - pad * 2) / (maxY - minY))));
    dispatch({
      type: "set-view",
      view: {
        x: (rect.width - (maxX - minX) * z) / 2 - minX * z,
        y: (rect.height - (maxY - minY) * z) / 2 - minY * z,
        z,
      },
    });
  }

  function tidy() {
    const columns: Partial<Record<NodeType, number>> = {
      transaction: 20, routeif: 240, lookup: 240, getfield: 470, constant: 470,
      compare: 700, inlist: 700, contains: 700, booland: 920, boolor: 920, boolnot: 920,
      decision: 1130, aggregate: 1360, policy: 1360,
    };
    const nextY: Record<number, number> = {};
    for (const n of [...state.nodes].sort((a, b) => a.y - b.y)) {
      const x = columns[n.type] ?? 470;
      const y = nextY[x] ?? 30;
      dispatch({ type: "move-node", id: n.id, x, y });
      nextY[x] = y + 180;
    }
    requestAnimationFrame(fitView);
  }

  /* ---- node dragging ---- */
  function onHeaderPointerDown(e: ReactPointerEvent, node: NodeModel) {
    if ((e.target as HTMLElement).closest("button, input, select")) return;
    e.preventDefault();
    const start = { sx: e.clientX, sy: e.clientY, nx: node.x, ny: node.y };
    const move = (ev: PointerEvent) => {
      const v = viewRef.current;
      dispatch({
        type: "move-node",
        id: node.id,
        x: start.nx + (ev.clientX - start.sx) / v.z,
        y: start.ny + (ev.clientY - start.sy) / v.z,
      });
    };
    const up = () => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  /* ---- wiring ---- */
  function onPortPointerDown(e: ReactPointerEvent, node: NodeModel, key: string, side: "in" | "out", type: string) {
    e.preventDefault();
    const index = portIndex(node.type, key, side);
    const anchor = portPosition(node, index, side);
    const move = (ev: PointerEvent) => {
      const cursor = screenToWorld(ev.clientX, ev.clientY);
      setTemp(side === "out" ? { a: anchor, b: cursor } : { a: cursor, b: anchor });
    };
    const up = (ev: PointerEvent) => {
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
      setTemp(null);
      const target = (document.elementFromPoint(ev.clientX, ev.clientY) as HTMLElement | null)?.closest<HTMLElement>("[data-port-node]");
      if (target === null || target === undefined) return;
      const otherSide = target.dataset["portSide"];
      const otherType = target.dataset["portType"];
      if (otherSide === side || otherType !== type) return;
      const other = { node: Number(target.dataset["portNode"]), key: String(target.dataset["portKey"]) };
      const self = { node: node.id, key };
      dispatch(side === "out" ? { type: "add-wire", from: self, to: other } : { type: "add-wire", from: other, to: self });
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  /* ---- panning ---- */
  function onBackgroundPointerDown(e: ReactPointerEvent) {
    const target = e.target as HTMLElement;
    if (target.closest(".gnode, .gport, .toolbar, .legend, .zoombar")) return;
    const v = viewRef.current;
    const start = { sx: e.clientX, sy: e.clientY, ox: v.x, oy: v.y };
    setPanning(true);
    const move = (ev: PointerEvent) => {
      dispatch({ type: "set-view", view: { x: start.ox + (ev.clientX - start.sx), y: start.oy + (ev.clientY - start.sy), z: viewRef.current.z } });
    };
    const up = () => {
      setPanning(false);
      window.removeEventListener("pointermove", move);
      window.removeEventListener("pointerup", up);
    };
    window.addEventListener("pointermove", move);
    window.addEventListener("pointerup", up);
  }

  const hotColor = evaluation.final === "allow" ? "var(--allow)" : "var(--deny)";

  // Frame the whole graph on mount and whenever a batch of nodes is added
  // (e.g. "Convert to route"), so freshly scaffolded branches come into view.
  useEffect(() => {
    const raf = requestAnimationFrame(fitView);
    return () => cancelAnimationFrame(raf);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [state.fitNonce]);

  return (
    <div
      ref={wrapRef}
      className={`canvaswrap ${panning ? "panning" : ""} ${dropOk ? "dropok" : ""}`}
      onPointerDown={onBackgroundPointerDown}
      onWheel={(e) => zoomAt(e.clientX, e.clientY, e.deltaY < 0 ? 1.12 : 1 / 1.12)}
      onDragOver={(e) => {
        e.preventDefault();
        setDropOk(true);
      }}
      onDragLeave={() => setDropOk(false)}
      onDrop={(e) => {
        e.preventDefault();
        setDropOk(false);
        const raw = e.dataTransfer.getData("text/plain");
        if (raw === "") return;
        const w = screenToWorld(e.clientX, e.clientY);
        dispatch({ type: "add-node", nodeType: raw as NodeType, x: w.x - NODE_W / 2, y: w.y - 24 });
      }}
    >
      <div className="toolbar">
        <button className="ghostbtn" onClick={tidy}>Auto-arrange</button>
        <button className="ghostbtn" onClick={() => { dispatch({ type: "reset-demo" }); requestAnimationFrame(fitView); }}>Reset demo</button>
      </div>
      <div
        className="world"
        style={{ transform: `translate(${state.view.x}px, ${state.view.y}px) scale(${state.view.z})` }}
      >
        <Wires
          nodes={state.nodes}
          wires={state.wires}
          hotWires={evaluation.hotWires}
          hotColor={hotColor}
          temp={temp}
          onDeleteWire={(wire) => dispatch({ type: "delete-wire", wire })}
        />
        {state.nodes.map((node) => (
          <GraphNodeView
            key={node.id}
            node={node}
            selected={state.selected === node.id}
            hot={evaluation.hotNodes.has(node.id) && evaluation.governingId !== null}
            hotColor={hotColor}
            skipDim={node.type === "routeif" && evaluation.nodeValues.get(node.id) === SKIP}
            badge={formatBadge(evaluation.nodeValues.get(node.id))}
            onHeaderPointerDown={onHeaderPointerDown}
            onPortPointerDown={onPortPointerDown}
          />
        ))}
      </div>
      <div className="legend">
        <b style={{ color: "var(--tx)" }}><i />tx</b>
        <b style={{ color: "var(--val)" }}><i />value</b>
        <b style={{ color: "var(--bool)" }}><i />bool</b>
        <b style={{ color: "var(--verdict)" }}><i />verdict</b>
      </div>
      <div className="zoombar">
        <button className="ghostbtn" onClick={() => centerZoom(1 / 1.2)}>−</button>
        <button className="ghostbtn zoomlvl" onClick={() => dispatch({ type: "set-view", view: { x: 0, y: 0, z: 1 } })}>
          {Math.round(state.view.z * 100)}%
        </button>
        <button className="ghostbtn" onClick={() => centerZoom(1.2)}>+</button>
        <button className="ghostbtn" onClick={fitView}>Fit</button>
      </div>
    </div>
  );

  function centerZoom(factor: number) {
    const rect = wrapRef.current?.getBoundingClientRect();
    if (rect === undefined) return;
    zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, factor);
  }
}
