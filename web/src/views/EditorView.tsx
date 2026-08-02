/**
 * Policy editor view: palette · canvas · inspector, with the commit modal.
 *
 * When opened for an agent (Agents → "Edit policy"), it first LOADS that
 * agent's policy row from the SignBox contract on the selected network and
 * decompiles it into the graph — you edit what is actually deployed. Without
 * an agent it starts on the demo graph. The compiled policy carries the
 * chainId of the globally selected network.
 */

import { useCallback, useEffect, useMemo, useState } from "react";
import { useNetwork } from "../context/NetworkContext";
import { GraphProvider, useGraph, type GraphState } from "../editor/store";
import { HelpProvider, useHelp } from "../editor/help";
import { EditorTour, TOUR_SEEN_KEY } from "../editor/EditorTour";
import { GraphCanvas } from "../editor/GraphCanvas";
import { Inspector } from "../editor/Inspector";
import { PushModal } from "../editor/PushModal";
import { evaluateGraph } from "../editor/eval";
import { compilePolicy, type CompileResult } from "../editor/compile";
import { decompilePolicy } from "../editor/decompile";
import { SAMPLES } from "../editor/samples";
import { loadTestTxs, saveTestTx, deleteTestTx, txToSampleActions, TEST_CHAIN } from "../editor/testTx";
import { buildScaffold } from "../editor/scaffold";
import { collectLookupQueries, resolveLookups, canonForNode, type LookupEvidence } from "../editor/lookups";
import { getPolicy } from "../chain/rpc";
import { SIGNBOX_CONTRACT } from "../networks";
import type { NodeType, SampleAction, TestTx } from "../editor/types";

/** Resolve the picker's key ("builtin:N" | "custom:NAME") to simulator actions. */
function resolveActions(selected: string, customTxs: TestTx[]): SampleAction[] {
  if (selected.startsWith("custom:")) {
    const name = selected.slice("custom:".length);
    const found = customTxs.find((t) => t.name === name);
    if (found !== undefined) return txToSampleActions(found.tx);
    return SAMPLES[0]?.actions ?? [];
  }
  const idx = Number(selected.slice("builtin:".length));
  return SAMPLES[idx]?.actions ?? SAMPLES[0]?.actions ?? [];
}

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

function Palette({ onReplayTour }: { onReplayTour: () => void }) {
  const { dispatch } = useGraph();
  const { open: openHelp } = useHelp();
  const add = (type: NodeType) =>
    dispatch({ type: "add-node", nodeType: type, x: 400 + Math.random() * 60, y: 200 + Math.random() * 60 });
  return (
    <aside className="palette">
      {PALETTE.map((group) => (
        <div key={group.section}>
          <h3>{group.section}</h3>
          {group.entries.map((entry) => (
            <div
              key={entry.type}
              className="pbtn"
              role="button"
              tabIndex={0}
              style={{ ["--c" as string]: entry.color }}
              draggable
              onDragStart={(e) => {
                e.dataTransfer.setData("text/plain", entry.type);
                e.dataTransfer.effectAllowed = "copy";
              }}
              onClick={() => add(entry.type)}
              onKeyDown={(e) => {
                if (e.key === "Enter" || e.key === " ") {
                  e.preventDefault();
                  add(entry.type);
                }
              }}
            >
              <span className="sw" />
              <span className="pl">{entry.label}</span>
              <button
                className="pq"
                aria-label={`Help for ${entry.label}`}
                title="What is this node?"
                onClick={(e) => {
                  e.stopPropagation();
                  openHelp(entry.type);
                }}
              >
                ?
              </button>
            </div>
          ))}
        </div>
      ))}
      <p className="hint">
        A transaction flows in on the left and is <b>routed</b> to the rule sets whose Route If matches.
        Wire <b>Transaction → Route If → conditions → Decision → Policy</b>. Ports are typed — only matching
        colors connect. Pick a sample tx in the inspector to watch it route.
      </p>
      <button className="palettetour" onClick={onReplayTour} title="Replay the editor tour">
        ↻ Editor tour
      </button>
    </aside>
  );
}

interface LoadedPolicy {
  agent: string;
  version: number;
  warnings: string[];
}

function EditorInner({ loaded, onBack }: { loaded: LoadedPolicy; onBack: () => void }) {
  const { state, dispatch } = useGraph();
  const { chainId, network, endpoints } = useNetwork();
  const [modal, setModal] = useState<CompileResult | null>(null);
  // First-run walkthrough — shown once (localStorage flag), replayable from the palette.
  const [tourOpen, setTourOpen] = useState(() => {
    try {
      return localStorage.getItem(TOUR_SEEN_KEY) !== "1";
    } catch {
      return false;
    }
  });
  const closeTour = () => {
    setTourOpen(false);
    try {
      localStorage.setItem(TOUR_SEEN_KEY, "1");
    } catch {
      /* ignore */
    }
  };
  const [customTxs, setCustomTxs] = useState<TestTx[]>(() => loadTestTxs(network));
  const [selected, setSelected] = useState<string>("builtin:0");
  const [evidence, setEvidence] = useState<LookupEvidence>(new Map());
  const [lookupLoading, setLookupLoading] = useState(false);

  // Refresh the saved tests when the target network changes.
  useEffect(() => {
    setCustomTxs(loadTestTxs(network));
  }, [network]);

  const actions = useMemo(() => resolveActions(selected, customTxs), [selected, customTxs]);

  // Lookup nodes hit the real chain: gather their resolved queries, fetch each
  // once (debounced), and feed the evidence into the pure interpreter.
  const queries = useMemo(() => collectLookupQueries(state.nodes, actions), [state.nodes, actions]);
  const qsig = queries.map((q) => q.canon).sort().join("~");
  useEffect(() => {
    if (queries.length === 0) {
      setEvidence(new Map());
      setLookupLoading(false);
      return;
    }
    let alive = true;
    setLookupLoading(true);
    const t = setTimeout(() => {
      void resolveLookups(endpoints, queries).then((ev) => {
        if (!alive) return;
        setEvidence(ev);
        setLookupLoading(false);
      });
    }, 400);
    return () => {
      alive = false;
      clearTimeout(t);
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [qsig, network]);

  const resolver = useCallback(
    (fields: Record<string, string | boolean>, action: SampleAction) =>
      evidence.get(canonForNode(fields, action))?.row ?? null,
    [evidence],
  );

  const evaluation = useMemo(
    () => evaluateGraph(state.nodes, state.wires, actions, resolver),
    [state.nodes, state.wires, actions, resolver],
  );

  const onSaveTest = useCallback(
    (name: string, tx: unknown) => {
      saveTestTx({ name, tx, chain: TEST_CHAIN, network });
      setCustomTxs(loadTestTxs(network));
      setSelected(`custom:${name}`);
    },
    [network],
  );

  function onDeleteTest(name: string) {
    deleteTestTx(name, network);
    setCustomTxs(loadTestTxs(network));
    setSelected((prev) => (prev === `custom:${name}` ? "builtin:0" : prev));
  }

  // Scaffold the routing branch(es) for a transaction into the current graph.
  function onConvertToRoute(tx: unknown) {
    const scaffold = buildScaffold(state, tx);
    dispatch({ type: "add-scaffold", nodes: scaffold.nodes, wires: scaffold.wires, nextId: scaffold.nextId });
  }

  function onCommit() {
    const compiled = compilePolicy(state.nodes, state.wires, chainId);
    if (compiled !== null) setModal(compiled);
  }

  return (
    <HelpProvider>
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
        <Palette onReplayTour={() => setTourOpen(true)} />
        <GraphCanvas evaluation={evaluation} />
        <Inspector
          evaluation={evaluation}
          onCommit={onCommit}
          selected={selected}
          onSelect={setSelected}
          customTxs={customTxs}
          network={network}
          onSaveTest={onSaveTest}
          onConvertToRoute={onConvertToRoute}
          onDeleteTest={onDeleteTest}
          lookupLoading={lookupLoading}
        />
        {modal !== null && (
          <PushModal compiled={modal} preselect={loaded.agent} onClose={() => setModal(null)} />
        )}
        {tourOpen && <EditorTour onClose={closeTour} />}
      </div>
    </HelpProvider>
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
