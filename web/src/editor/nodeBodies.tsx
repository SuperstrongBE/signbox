/**
 * Per-type node field UIs. Every input dispatches set-field; pointer events
 * stop propagating so typing/clicking never starts a node drag.
 */

import type { ChangeEvent, ReactNode } from "react";
import type { GraphNode } from "./types";
import { useGraph } from "./store";

function Field({ label, children }: { label: string; children: ReactNode }) {
  return (
    <div className="gfield">
      <label>{label}</label>
      {children}
    </div>
  );
}

function stop(e: { stopPropagation: () => void }) {
  e.stopPropagation();
}

export function NodeBody({ node }: { node: GraphNode }) {
  const { dispatch } = useGraph();
  const f = node.fields;
  const set = (key: string) => (e: ChangeEvent<HTMLInputElement | HTMLSelectElement>) =>
    dispatch({ type: "set-field", id: node.id, key, value: e.target.value });
  const setBool = (key: string) => (e: ChangeEvent<HTMLInputElement>) =>
    dispatch({ type: "set-field", id: node.id, key, value: e.target.checked });

  const text = (key: string, placeholder?: string) => (
    <input value={String(f[key] ?? "")} placeholder={placeholder} onChange={set(key)} onPointerDown={stop} />
  );
  const select = (key: string, options: string[]) => {
    const current = String(f[key] ?? "");
    // A decompiled policy may carry a value outside the preset list (e.g. a
    // lookup field name) — keep it selectable instead of blanking the control.
    const all = current !== "" && !options.includes(current) ? [current, ...options] : options;
    return (
      <select value={current} onChange={set(key)} onPointerDown={stop}>
        {all.map((o) => (
          <option key={o} value={o}>{o}</option>
        ))}
      </select>
    );
  };
  const check = (key: string, label: string) => (
    <label className="gchk" onPointerDown={stop}>
      <input type="checkbox" checked={f[key] === true} onChange={setBool(key)} />
      {label}
    </label>
  );
  // Free-text input with preset suggestions — type a custom path or pick one.
  const combo = (key: string, options: string[], placeholder?: string) => {
    const listId = `dl-${node.id}-${key}`;
    return (
      <>
        <input list={listId} value={String(f[key] ?? "")} placeholder={placeholder} onChange={set(key)} onPointerDown={stop} />
        <datalist id={listId}>
          {options.map((o) => (<option key={o} value={o} />))}
        </datalist>
      </>
    );
  };

  switch (node.type) {
    case "transaction":
      return <div className="gempty">→ the incoming action (pick a sample in the inspector)</div>;
    case "routeif":
      return (
        <div className="grow2">
          <Field label="contract">{text("contract")}</Field>
          <Field label="action">{text("action")}</Field>
        </div>
      );
    case "getfield":
      return (
        <Field label="field path (custom)">
          {combo("path", ["contract", "action", "data.from", "data.to", "data.quantity.amount", "data.quantity.symbol", "data.memo", "allowed", "tier"], "data.your_field")}
        </Field>
      );
    case "constant":
      return <Field label="value">{text("value")}</Field>;
    case "compare":
      return (
        <>
          <Field label="op">{select("op", ["lte", "gte", "lt", "gt", "eq", "neq", "between"])}</Field>
          <Field label="value">{text("value", "1.0000 or 1,5")}</Field>
        </>
      );
    case "inlist":
      return (
        <>
          <Field label="mode">{select("mode", ["in", "notin"])}</Field>
          <Field label="list (comma)">{text("list")}</Field>
        </>
      );
    case "contains":
      return <Field label="value">{text("value", "$data.to")}</Field>;
    case "booland":
    case "boolor":
      return <div className="gempty">combine inputs</div>;
    case "boolnot":
      return <div className="gempty">¬ input</div>;
    case "lookup":
      return (
        <>
          <Field label="source">{select("mode", ["table", "http"])}</Field>
          {f["mode"] === "http" ? (
            <>
              <Field label="url">{text("url", "https://api.example.com/…")}</Field>
              <Field label="json path">{text("httpPath", "data.0.value")}</Field>
              <div className="glimbadge">⚠ HTTP · test-only · NOT enforced by the daemon (omitted from the pushed policy)</div>
            </>
          ) : (
            <>
              <div className="grow2">
                <Field label="contract">{text("contract")}</Field>
                <Field label="table">{text("table")}</Field>
              </div>
              <Field label="key">{text("key", "$agent")}</Field>
              <div className="gempty">provider: xpr.rpc.tableRow · enforced on-chain</div>
            </>
          )}
        </>
      );
    case "decision":
      return (
        <>
          <Field label="effect">
            <div className="gseg" onPointerDown={stop}>
              {(["allow", "deny"] as const).map((v) => (
                <button
                  key={v}
                  className={f["effect"] === v ? `on-${v}` : ""}
                  onClick={() => dispatch({ type: "set-field", id: node.id, key: "effect", value: v })}
                >
                  {v}
                </button>
              ))}
            </div>
          </Field>
          {check("useLimit", "＋ limits (auto-aggregated)")}
          {f["useLimit"] === true && (
            <div className="gsub" style={{ ["--sc" as string]: "var(--bool)" }}>
              <Field label="max per transaction · Σ actions">{text("maxPerTx", "1.0000 XPR")}</Field>
              <div className="grow2">
                <Field label="max count">{text("rlCount", "1")}</Field>
                <Field label="per period">{select("rlPeriod", ["hour", "day"])}</Field>
              </div>
              {check("rlPerRecipient", "per recipient")}
              <Field label="cooldown per recipient (hours)">{text("cooldownH", "24")}</Field>
              <div className="glimbadge">🕒 rate limit &amp; cooldown: local best-effort · sliding window · cross-tx</div>
            </div>
          )}
        </>
      );
    case "aggregate":
      return (
        <>
          <Field label="max total / tx · all rules">{text("maxTotal")}</Field>
          <div className="glimbadge">⚙ advanced · cross-rule ceiling (opt-in)</div>
        </>
      );
    case "policy":
      return (
        <>
          <Field label="max actions / tx">{text("maxActions", "1")}</Field>
          <Field label="default (nothing matched)">{select("default", ["deny", "allow"])}</Field>
          <div className="glimbadge">🛡 default 1 · multi-action refused unless raised</div>
        </>
      );
    default:
      return null;
  }
}
