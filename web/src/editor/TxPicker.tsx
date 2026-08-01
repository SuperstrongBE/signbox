/**
 * The incoming-transaction picker. A custom dropdown (not a native <select>)
 * so each saved test can carry per-row actions: select it, convert it into a
 * route branch, or delete it. Built-in samples are select-only.
 */

import { useEffect, useRef, useState } from "react";
import type { TestTx } from "./types";
import { SAMPLES } from "./samples";

function selectedLabel(selected: string, customTxs: TestTx[]): string {
  if (selected.startsWith("custom:")) {
    const name = selected.slice("custom:".length);
    return customTxs.some((t) => t.name === name) ? name : "—";
  }
  const idx = Number(selected.slice("builtin:".length));
  return SAMPLES[idx]?.label ?? "—";
}

export function TxPicker({
  selected,
  onSelect,
  customTxs,
  onConvertToRoute,
  onDelete,
}: {
  selected: string;
  onSelect: (key: string) => void;
  customTxs: TestTx[];
  onConvertToRoute: (tx: unknown) => void;
  onDelete: (name: string) => void;
}) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!open) return;
    const onDoc = (e: MouseEvent) => {
      if (ref.current !== null && !ref.current.contains(e.target as Node)) setOpen(false);
    };
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") setOpen(false);
    };
    document.addEventListener("mousedown", onDoc);
    window.addEventListener("keydown", onKey);
    return () => {
      document.removeEventListener("mousedown", onDoc);
      window.removeEventListener("keydown", onKey);
    };
  }, [open]);

  return (
    <div className="txsel" ref={ref}>
      <button
        className="txseltrigger"
        aria-haspopup="listbox"
        aria-expanded={open}
        onClick={() => setOpen((o) => !o)}
      >
        <span className="txsellabel">{selectedLabel(selected, customTxs)}</span>
        <span className="txselcaret">▾</span>
      </button>

      {open && (
        <div className="txselmenu" role="listbox">
          <div className="txselgroup">Samples</div>
          {SAMPLES.map((s, i) => {
            const key = `builtin:${i}`;
            return (
              <button
                key={key}
                className={`txselopt ${selected === key ? "sel" : ""}`}
                role="option"
                aria-selected={selected === key}
                onClick={() => {
                  onSelect(key);
                  setOpen(false);
                }}
              >
                {s.label}
              </button>
            );
          })}

          {customTxs.length > 0 && <div className="txselgroup">Your tests</div>}
          {customTxs.map((t) => {
            const key = `custom:${t.name}`;
            return (
              <div key={t.name} className={`txselrow ${selected === key ? "sel" : ""}`}>
                <button
                  className="txselopt grow"
                  role="option"
                  aria-selected={selected === key}
                  onClick={() => {
                    onSelect(key);
                    setOpen(false);
                  }}
                >
                  {t.name}
                </button>
                <button
                  className="txselact"
                  title="Convert this test into a route branch"
                  aria-label={`Convert ${t.name} to a route`}
                  onClick={() => {
                    onConvertToRoute(t.tx);
                    setOpen(false);
                  }}
                >
                  → route
                </button>
                <button
                  className="txseldel"
                  title="Delete this test"
                  aria-label={`Delete ${t.name}`}
                  onClick={() => onDelete(t.name)}
                >
                  ✕
                </button>
              </div>
            );
          })}
        </div>
      )}
    </div>
  );
}
