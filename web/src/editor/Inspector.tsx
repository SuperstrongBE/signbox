/**
 * Inspector: sample picker, incoming-tx summary, the explicit evaluation trace
 * (per-condition breakdown including lookup results), the final verdict, and
 * the commit button. Multi-action samples show the three-tier breakdown.
 */

import { useState, type ReactNode } from "react";
import type { GraphNode, SampleAction, TestTx } from "./types";
import { TestTxModal } from "./TestTxModal";
import { TxPicker } from "./TxPicker";
import { useGraph } from "./store";
import {
  SKIP,
  inboundNodes,
  ruleLabel,
  substitute,
  upstream,
  type Evaluation,
  type Value,
} from "./eval";

function fmtValue(v: unknown): string {
  if (v === undefined || v === null) return "—";
  if (Array.isArray(v)) return `[${v.slice(0, 4).map(String).join(", ")}${v.length > 4 ? ", …" : ""}]`;
  if (typeof v === "object") {
    const keys = Object.keys(v as object);
    return keys.length > 0 ? `{${keys[0]}: …}` : "{…}";
  }
  return String(v);
}

function fmtLookup(v: unknown): string {
  if (v !== null && typeof v === "object" && !Array.isArray(v)) {
    const obj = v as Record<string, unknown>;
    const keys = Object.keys(obj);
    const shown = keys.slice(0, 5).map((k) => `${k}: ${fmtValue(obj[k])}`).join(", ");
    return `{${shown}${keys.length > 5 ? ", …" : ""}}`;
  }
  return fmtValue(v);
}

function Step({ label, value, kind }: { label: string; value: string; kind: "ok" | "no" | "info" }) {
  return (
    <div className="step">
      <span>{label}</span>
      <span className={`r ${kind}`}>{value}</span>
    </div>
  );
}

function TraceCard({ title, tag, tagClass, win, winColor, children }: {
  title: ReactNode;
  tag: string;
  tagClass: string;
  win?: boolean;
  winColor?: string;
  children?: ReactNode;
}) {
  return (
    <div className={`tracecard ${win === true ? "win" : ""}`} style={win === true ? { ["--wc" as string]: winColor ?? "var(--deny)" } : undefined}>
      <div className="th">
        {title}
        <span className={`vtag ${tagClass}`}>{tag}</span>
      </div>
      {children !== undefined && <div className="steps">{children}</div>}
    </div>
  );
}

/** Per-condition breakdown of one rule set, using the evaluated node values. */
function ruleSteps(
  nodes: GraphNode[],
  wires: { from: { node: number; key: string }; to: { node: number; key: string } }[],
  decision: GraphNode,
  values: Map<number, Value>,
  routed: boolean,
  action: SampleAction,
): ReactNode[] {
  const up = [...upstream(wires, decision.id)]
    .map((id) => nodes.find((n) => n.id === id))
    .filter((n): n is GraphNode => n !== undefined);
  const out: ReactNode[] = [];
  const routeif = up.find((n) => n.type === "routeif");
  if (routeif !== undefined) {
    const v = values.get(routeif.id);
    out.push(
      <Step
        key="route"
        label={`route if · ${routeif.fields["contract"]}::${routeif.fields["action"] || "*"}`}
        value={v === SKIP ? "skip" : "match"}
        kind={v === SKIP ? "no" : "ok"}
      />,
    );
  }
  if (!routed) return out;
  const order: Record<string, number> = { lookup: 1, compare: 2, inlist: 3, contains: 4 };
  for (const n of up.filter((x) => order[x.type] !== undefined).sort((a, b) => (order[a.type] ?? 9) - (order[b.type] ?? 9))) {
    const f = n.fields;
    if (n.type === "lookup") {
      const lv = values.get(n.id);
      const empty = lv === null || lv === undefined;
      out.push(
        <Step
          key={n.id}
          label={`lookup · ${f["table"]}[${substitute(String(f["key"]), action)}]`}
          value={empty ? "no row (not found / unreachable)" : fmtLookup(lv)}
          kind={empty ? "no" : "info"}
        />,
      );
    } else if (n.type === "compare") {
      const src = inboundNodes(nodes, wires, n.id, "a")[0];
      const a = src !== undefined ? values.get(src.id) : undefined;
      const ok = values.get(n.id) === true;
      const path = src !== undefined && src.type === "getfield" ? String(src.fields["path"]).replace(/^data\./, "") : "value";
      out.push(<Step key={n.id} label={`${path} ${f["op"]} ${f["value"]}`} value={`${fmtValue(a)} → ${ok}`} kind={ok ? "ok" : "no"} />);
    } else if (n.type === "inlist") {
      const src = inboundNodes(nodes, wires, n.id, "a")[0];
      const a = src !== undefined ? values.get(src.id) : undefined;
      const ok = values.get(n.id) === true;
      const path = src !== undefined && src.type === "getfield" ? String(src.fields["path"]).replace(/^data\./, "") : "value";
      out.push(<Step key={n.id} label={`${path} ${f["mode"] === "notin" ? "not in" : "in"} list`} value={`${fmtValue(a)} → ${ok}`} kind={ok ? "ok" : "no"} />);
    } else if (n.type === "contains") {
      const src = inboundNodes(nodes, wires, n.id, "a")[0];
      const arr = src !== undefined ? values.get(src.id) : undefined;
      const ok = values.get(n.id) === true;
      const path = src !== undefined && src.type === "getfield" ? String(src.fields["path"]) : "array";
      // Contains needs a list input; a scalar can never match — spell that out.
      const rhs = Array.isArray(arr) ? `${fmtValue(arr)} → ${ok}` : `${fmtValue(arr)} is not a list → ${ok}`;
      out.push(<Step key={n.id} label={`${path} contains “${substitute(String(f["value"]), action)}”`} value={rhs} kind={ok ? "ok" : "no"} />);
    }
  }
  return out;
}

export function Inspector({
  evaluation,
  onCommit,
  selected,
  onSelect,
  customTxs,
  network,
  onSaveTest,
  onConvertToRoute,
  onDeleteTest,
  lookupLoading,
}: {
  evaluation: Evaluation;
  onCommit: () => void;
  selected: string;
  onSelect: (key: string) => void;
  customTxs: TestTx[];
  network: string;
  onSaveTest: (name: string, tx: unknown) => void;
  onConvertToRoute: (tx: unknown) => void;
  onDeleteTest: (name: string) => void;
  lookupLoading: boolean;
}) {
  const { state } = useGraph();
  const [showAdd, setShowAdd] = useState(false);
  const actions = evaluation.perAction.map((p) => p.action);
  const first = actions[0] as SampleAction | undefined;
  const multi = actions.length > 1;
  const hotColor = evaluation.final === "allow" ? "var(--allow)" : "var(--deny)";
  const hasRules = state.nodes.some((n) => n.type === "decision");

  return (
    <aside className="inspector">
      <div className="isec">
        <h4>Incoming transaction</h4>
        <div className="txpickrow">
          <TxPicker
            selected={selected}
            onSelect={onSelect}
            customTxs={customTxs}
            onConvertToRoute={onConvertToRoute}
            onDelete={onDeleteTest}
          />
          <button
            className="txaddbtn"
            title="Add a custom test transaction"
            aria-label="Add a custom test transaction"
            onClick={() => setShowAdd(true)}
          >
            +
          </button>
        </div>
        {first !== undefined && (
          <div className="txbox">
            {multi ? (
              <>
                <span className="a">{actions.length} actions</span> <span className="m">— each</span>{" "}
                {first.contract}::{first.action} {first.data.quantity.amount} {first.data.quantity.symbol} →{" "}
                {first.data.to} <span className="m">(×{actions.length})</span>
              </>
            ) : (
              <>
                <span className="a">{first.contract}::{first.action}</span>
                <br />
                <span className="m">from</span> {first.data.from}
                {first.data.to !== "" && (<><br /><span className="m">to</span> {first.data.to}</>)}
                {first.data.quantity.amount !== "" && (
                  <><br /><span className="m">quantity</span> {first.data.quantity.amount} {first.data.quantity.symbol}</>
                )}
              </>
            )}
          </div>
        )}
      </div>

      <div className="isec">
        <h4>Evaluation trace{lookupLoading && <span className="lookupbusy"> · querying chain…</span>}</h4>
        <div className="trace">
          {!hasRules && <div className="gempty">Add Decision nodes wired to a Policy.</div>}

          {hasRules && multi && (
            <>
              <TraceCard
                title={<>① Max actions / tx <span className="mono" style={{ color: "var(--mut2)", fontSize: 9 }}>floor</span></>}
                tag={`${actions.length} / ${evaluation.maxActions}`}
                tagClass={evaluation.tooMany ? "deny" : "allow"}
                win={evaluation.decidedBy === "maxActions"}
              >
                {evaluation.decidedBy === "maxActions" && (
                  <Step label="multi-action refused unless the policy raises the cap" value="TOO_MANY_ACTIONS" kind="no" />
                )}
              </TraceCard>
              {evaluation.perAction.map((p, i) => (
                <TraceCard
                  key={i}
                  title={<>Action {i + 1} · <span className="mono" style={{ fontSize: 10.5 }}>{p.action.contract}::{p.action.action}</span></>}
                  tag={p.verdict.toUpperCase()}
                  tagClass={p.verdict}
                />
              ))}
              <RuleLimitsCard evaluation={evaluation} />
              {state.nodes.some((n) => n.type === "aggregate") && (
                <TraceCard
                  title={<>③ Global cap <span className="mono" style={{ color: "var(--mut2)", fontSize: 9 }}>opt-in</span></>}
                  tag={evaluation.globalCap !== null ? "EXCEEDED" : "OK"}
                  tagClass={evaluation.globalCap !== null ? "deny" : "allow"}
                  win={evaluation.decidedBy === "globalCap"}
                >
                  <Step
                    label="Σ transfers (all rules)"
                    value={evaluation.globalCap !== null ? `${evaluation.globalCap.sum.toFixed(4)} / ${evaluation.globalCap.cap.toFixed(4)} XPR` : "within cap"}
                    kind={evaluation.globalCap !== null ? "no" : "ok"}
                  />
                </TraceCard>
              )}
            </>
          )}

          {hasRules && !multi && first !== undefined && (evaluation.perAction[0]?.decisions ?? []).map((r) => (
            <TraceCard
              key={r.node.id}
              title={ruleLabel(state.nodes, state.wires, r.node)}
              tag={r.routed ? (r.verdict !== null ? r.verdict.toUpperCase() : "no-match") : "skip"}
              tagClass={r.routed ? (r.verdict ?? "skip") : "skip"}
              win={evaluation.governingId === r.node.id}
              winColor={hotColor}
            >
              {ruleSteps(state.nodes, state.wires, r.node, evaluation.nodeValues, r.routed, first)}
            </TraceCard>
          ))}
        </div>
      </div>

      <div className="isec">
        <h4>Final decision</h4>
        <div className={`finalbig ${evaluation.final}`}>{evaluation.final === "allow" ? "✓ SIGN" : "✕ REFUSE"}</div>
        <div className="freason">{evaluation.reason}</div>
      </div>

      <div className="inspfoot">
        <button className="pushbtn" onClick={onCommit} disabled={!hasRules}>
          Commit policy on-chain →
        </button>
      </div>

      {showAdd && (
        <TestTxModal
          network={network}
          onSave={(name, tx) => {
            onSaveTest(name, tx);
            setShowAdd(false);
          }}
          onConvertToRoute={(tx) => {
            onConvertToRoute(tx);
            setShowAdd(false);
          }}
          onClose={() => setShowAdd(false)}
        />
      )}
    </aside>
  );
}

function RuleLimitsCard({ evaluation }: { evaluation: Evaluation }) {
  const ra = evaluation.ruleAgg;
  let detail: string;
  let kind: "ok" | "no" = "ok";
  if (ra !== null) {
    kind = "no";
    detail = ra.kind === "cap"
      ? `Σ ${ra.sum?.toFixed(4)} / ${ra.cap?.toFixed(4)} XPR — exceeded`
      : `${ra.count} → ${ra.recipient} / ${ra.limit} per ${ra.period} — exceeded`;
  } else {
    // Live Σ/cap so edits are visible even when within limits.
    const group = evaluation.perAction.filter((p) => p.verdict === "allow" && p.governing !== null && p.governing.fields["useLimit"] === true);
    const dec = group[0]?.governing;
    if (dec !== undefined && dec !== null && String(dec.fields["maxPerTx"] ?? "") !== "") {
      let sum = 0;
      for (const p of group) {
        const x = parseFloat(p.action.data.quantity.amount);
        if (!isNaN(x)) sum += x;
      }
      const cap = parseFloat(String(dec.fields["maxPerTx"]).split(" ")[0] ?? "");
      detail = `Σ ${sum.toFixed(4)} / ${isNaN(cap) ? "—" : cap.toFixed(4)} XPR · within cap`;
    } else {
      detail = "maxPerTransaction & rate limits sum across all actions — no node needed";
    }
  }
  return (
    <TraceCard
      title={<>② Rule limits <span className="mono" style={{ color: "var(--mut2)", fontSize: 9 }}>auto</span></>}
      tag={ra !== null ? "EXCEEDED" : "OK"}
      tagClass={ra !== null ? "deny" : "allow"}
      win={evaluation.decidedBy === "ruleAgg"}
    >
      <Step label="per-rule aggregation" value={detail} kind={kind} />
    </TraceCard>
  );
}
