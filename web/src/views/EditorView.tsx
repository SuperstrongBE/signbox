/**
 * Policy editor view: palette · canvas · inspector, with the commit modal.
 *
 * When opened for an agent (Agents → "Edit policy"), it first LOADS that
 * agent's policy row from the SignBox contract on the selected network and
 * decompiles it into the graph — you edit what is actually deployed. Without
 * an agent it starts on the demo graph. The compiled policy carries the
 * chainId of the globally selected network.
 */

import { useEffect, useMemo, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { GraphProvider, useGraph, type GraphState } from "../editor/store";
import { GraphCanvas } from "../editor/GraphCanvas";
import { Inspector } from "../editor/Inspector";
import { PushModal } from "../editor/PushModal";
import { evaluateGraph } from "../editor/eval";
import { compilePolicy, type CompileResult } from "../editor/compile";
import { decompilePolicy } from "../editor/decompile";
import { SAMPLES } from "../editor/samples";
import { getPolicy } from "../chain/rpc";
import { SIGNBOX_CONTRACT } from "../networks";
import type { NodeType } from "../editor/types";

interface PaletteEntry {
  type: NodeType;
  label: string;
  color: string;
}

const PALETTE: { section: string; entries: PaletteEntry[] }[] = [
  {
    section: "Flow",
    entries: [
      { type: "transaction", label: "Incoming transaction", color: "var(--tx)" },
      { type: "policy", label: "Global Policy", color: "var(--neutral)" },
    ],
  },
  {
    section: "Route",
    entries: [{ type: "routeif", label: "Route If", color: "var(--tx)" }],
  },
  {
    section: "Data",
    entries: [
      { type: "getfield", label: "Get Field", color: "var(--val)" },
      { type: "constant", label: "Constant", color: "var(--val)" },
      { type: "lookup", label: "Lookup (JSON)", color: "var(--lookup)" },
    ],
  },
  {
    section: "Compare",
    entries: [
      { type: "compare", label: "Compare", color: "var(--val)" },
      { type: "inlist", label: "In List", color: "var(--val)" },
      { type: "contains", label: "Contains", color: "var(--val)" },
    ],
  },
  {
    section: "Boolean",
    entries: [
      { type: "booland", label: "AND", color: "var(--bool)" },
      { type: "boolor", label: "OR", color: "var(--bool)" },
      { type: "boolnot", label: "NOT", color: "var(--bool)" },
    ],
  },
  {
    section: "Decision",
    entries: [
      { type: "decision", label: "Decision (+ limits)", color: "var(--allow)" },
      { type: "aggregate", label: "Global cap · advanced", color: "var(--bool)" },
    ],
  },
];

function Palette() {
  const { dispatch } = useGraph();
  return (
    <aside className="palette">
      {PALETTE.map((group) => (
        <div key={group.section}>
          <h3>{group.section}</h3>
          {group.entries.map((entry) => (
            <button
              key={entry.type}
              className="pbtn"
              style={{ ["--c" as string]: entry.color }}
              draggable
              onDragStart={(e) => {
                e.dataTransfer.setData("text/plain", entry.type);
                e.dataTransfer.effectAllowed = "copy";
              }}
              onClick={() => dispatch({ type: "add-node", nodeType: entry.type, x: 400 + Math.random() * 60, y: 200 + Math.random() * 60 })}
            >
              <span className="sw" />
              {entry.label}
            </button>
          ))}
        </div>
      ))}
      <p className="hint">
        A transaction flows in on the left and is <b>routed</b> to the rule sets whose Route If matches.
        Wire <b>Transaction → Route If → conditions → Decision → Policy</b>. Ports are typed — only matching
        colors connect. Pick a sample tx in the inspector to watch it route.
      </p>
    </aside>
  );
}

interface LoadedPolicy {
  agent: string;
  version: number;
  warnings: string[];
}

function EditorInner({ loaded, onBack }: { loaded: LoadedPolicy; onBack: () => void }) {
  const { state } = useGraph();
  const { chainId, network } = useNetwork();
  const [modal, setModal] = useState<CompileResult | null>(null);

  const sample = SAMPLES[state.sampleIdx] ?? SAMPLES[0];
  const evaluation = useMemo(
    () => evaluateGraph(state.nodes, state.wires, sample?.actions ?? []),
    [state.nodes, state.wires, sample],
  );

  function onCommit() {
    const compiled = compilePolicy(state.nodes, state.wires, chainId);
    if (compiled !== null) setModal(compiled);
  }

  return (
    <div className="editor">
      <div className="editbanner">
        <button className="backbtn" onClick={onBack}>← Agents</button>
        <span className="ebsep" />
        Editing <b className="mono">{loaded.agent}</b> · v{loaded.version} on {network}
        {loaded.warnings.length > 0 && (
          <span className="ebwarn" title={loaded.warnings.join("\n")}>
            ⚠ {loaded.warnings.length} construct{loaded.warnings.length > 1 ? "s" : ""} not shown
          </span>
        )}
      </div>
      <Palette />
      <GraphCanvas evaluation={evaluation} />
      <Inspector evaluation={evaluation} onCommit={onCommit} />
      {modal !== null && (
        <PushModal compiled={modal} preselect={loaded.agent} onClose={() => setModal(null)} />
      )}
    </div>
  );
}

type LoadState =
  | { kind: "loading" }
  | { kind: "error"; message: string }
  | { kind: "ready"; initial: GraphState; loaded: LoadedPolicy };

export function EditorView({ agent, onBack }: { agent: string; onBack: () => void }) {
  const { network, endpoints } = useNetwork();
  const [load, setLoad] = useState<LoadState>({ kind: "loading" });

  useEffect(() => {
    let alive = true;
    setLoad({ kind: "loading" });
    void (async () => {
      try {
        const row = await getPolicy(endpoints, SIGNBOX_CONTRACT, agent);
        if (!alive) return;
        if (row === null) {
          setLoad({ kind: "error", message: `no policy row for "${agent}" on ${network}` });
          return;
        }
        const { state, warnings } = decompilePolicy(row.policyjson);
        setLoad({ kind: "ready", initial: state, loaded: { agent, version: row.version, warnings } });
      } catch (error) {
        if (!alive) return;
        setLoad({ kind: "error", message: error instanceof Error ? error.message : String(error) });
      }
    })();
    return () => {
      alive = false;
    };
  }, [agent, endpoints, network]);

  if (load.kind === "loading") {
    return (
      <div className="editor">
        <div className="editstate">
          <div><button className="backbtn" onClick={onBack}>← Agents</button></div>
          Loading <b className="mono">{agent}</b>&apos;s policy from {network}…
        </div>
      </div>
    );
  }
  if (load.kind === "error") {
    return (
      <div className="editor">
        <div className="editstate error">
          <div><button className="backbtn" onClick={onBack}>← Agents</button></div>
          Could not load the policy: {load.message}
        </div>
      </div>
    );
  }
  return (
    <GraphProvider initial={load.initial}>
      <EditorInner loaded={load.loaded} onBack={onBack} />
    </GraphProvider>
  );
}
