/**
 * The `?` help modal for a node type. Structural port info comes from SPECS,
 * the prose from NODE_DOCS. Rendered by <HelpProvider> so any node header or
 * palette entry can open it.
 */

import { useEffect, type CSSProperties } from "react";
import type { NodeType, PortSpec } from "./types";
import { SPECS } from "./nodeSpecs";
import { NODE_DOCS } from "./nodeDocs";

const TYPE_COLOR: Record<string, string> = {
  tx: "var(--tx)",
  val: "var(--val)",
  bool: "var(--bool)",
  verdict: "var(--verdict)",
};

const pc = (type: string): CSSProperties => ({ ["--pc" as string]: TYPE_COLOR[type] });

export function NodeHelpModal({ type, onClose }: { type: NodeType; onClose: () => void }) {
  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const spec = SPECS[type];
  const doc = NODE_DOCS[type];
  const ins = spec.ports.filter((p) => p.side === "in");
  const outs = spec.ports.filter((p) => p.side === "out");

  const portItem = (p: PortSpec) => (
    <div className="nhitem" key={`${p.side}:${p.key}`}>
      <span className="nhidot" style={pc(p.type)} />
      <div className="nhcol">
        <span className="nhk">{p.label.replace(/^→ /, "")}</span>
        <span className="nhbadge" style={pc(p.type)}>{p.type}</span>
        <div className="nhd">{doc.portDesc[p.key] ?? ""}</div>
      </div>
    </div>
  );

  return (
    <div className="nhbg" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="nhcard" role="dialog" aria-modal="true" aria-label={`${spec.title} help`} style={{ ["--c" as string]: spec.color }}>
        <div className="nhtop">
          <span className="nhsw" />
          <h2>{spec.title}</h2>
          <span className="nhchip">{doc.cat}</span>
          <button className="nhx" aria-label="Close" onClick={onClose}>×</button>
        </div>
        <p className="nhsub">{doc.subtitle}</p>

        <div className="nhgrid">
          <div className="nhschem">
            <p className="nhcap">On the canvas</p>
            <div className="nhnode">
              <div className="nhhd">
                <span className="nhsw2" />
                <span className="nhttl">{spec.title}</span>
                <span className="nhq" aria-hidden="true">?</span>
              </div>
              <div className="nhbody">
                {ins.map((p) => (
                  <div className="nhprow" key={`i${p.key}`}><span className="nhdot" style={pc(p.type)} /><span>{p.label}</span></div>
                ))}
                {outs.map((p) => (
                  <div className="nhprow out" key={`o${p.key}`}><span>{p.label}</span><span className="nhdot" style={pc(p.type)} /></div>
                ))}
              </div>
            </div>
          </div>

          <div>
            {ins.length > 0 && <section className="nhsect"><h3>Inputs</h3>{ins.map(portItem)}</section>}
            {outs.length > 0 && <section className="nhsect"><h3>Outputs</h3>{outs.map(portItem)}</section>}
            {doc.fields.length > 0 && (
              <section className="nhsect">
                <h3>Parameters</h3>
                {doc.fields.map((f) => (
                  <div className="nhitem" key={f.name}>
                    <div className="nhcol">
                      <span className="nhk">{f.name}</span> <span className="nhrng">{f.range}</span>
                      <div className="nhd">{f.desc}</div>
                    </div>
                  </div>
                ))}
              </section>
            )}
          </div>
        </div>

        {doc.notes !== undefined && <div className="nhnote"><b>Note</b> — {doc.notes}</div>}
      </div>
    </div>
  );
}
