/**
 * First-run walkthrough of the editor: drag → help → test → convert → edit.
 * Shown once (localStorage flag, set on close) and re-openable from the palette.
 */

import { useEffect, useState, type CSSProperties, type ReactNode } from "react";

export const TOUR_SEEN_KEY = "signbox-editor-tour-seen";

const V = { tx: "var(--tx)", val: "var(--val)", allow: "var(--allow)" };
const cv = (c: string): CSSProperties => ({ ["--c" as string]: c });
const pv = (c: string): CSSProperties => ({ ["--pc" as string]: c });

function MiniNode({
  color,
  title,
  ports = [],
  glow = false,
  children,
}: {
  color: string;
  title: string;
  ports?: { label: string; color: string; out?: boolean }[];
  glow?: boolean;
  children?: ReactNode;
}) {
  return (
    <div className="mininode" style={cv(color)}>
      <div className="mh">
        <span className="sw" />
        <span>{title}</span>
        {glow && <span className="mq glow">?</span>}
      </div>
      {(ports.length > 0 || children !== undefined) && (
        <div className="mb">
          {ports.map((p, k) => (
            <div key={k} className={`prow ${p.out === true ? "out" : ""}`}>
              {p.out !== true && <span className="dot" style={pv(p.color)} />}
              <span>{p.label}</span>
              {p.out === true && <span className="dot" style={pv(p.color)} />}
            </div>
          ))}
          {children}
        </div>
      )}
    </div>
  );
}

interface Step {
  title: string;
  desc: ReactNode;
  visual: ReactNode;
}

const STEPS: Step[] = [
  {
    title: "Drag nodes onto the canvas",
    desc: (
      <>
        Build a policy from nodes. Drag them from the palette on the left onto the canvas, then wire{" "}
        <b>Transaction → Route If → conditions → Decision → Policy</b>. Ports are typed — only matching
        colours connect.
      </>
    ),
    visual: (
      <>
        <div className="pal-mini">
          <div className="pbtn-mini"><i style={{ background: V.tx }} />Route If</div>
          <div className="pbtn-mini lift"><i style={{ background: V.val }} />Get Field</div>
          <div className="pbtn-mini"><i style={{ background: V.allow }} />Decision</div>
        </div>
        <div className="arrow">→</div>
        <MiniNode color={V.val} title="Get Field" ports={[{ label: "data", color: V.val }, { label: "→ value", color: V.val, out: true }]} />
      </>
    ),
  },
  {
    title: "Not sure what a node does?",
    desc: (
      <>
        Hit the <code>?</code> on any node header — or any palette entry — for a full breakdown: its{" "}
        <b>inputs, outputs, parameters</b>, and the gotcha to watch.
      </>
    ),
    visual: (
      <>
        <MiniNode color={V.tx} title="Route If" glow ports={[{ label: "tx", color: V.tx }, { label: "→ matched", color: V.tx, out: true }]} />
        <div className="arrow">→</div>
        <div className="helppeek">
          <b>Inputs</b> · tx<br />
          <b>Outputs</b> · matched<br />
          <b>Parameters</b> · contract, action<br />
          <b>Note</b> · routing ≠ verdict
        </div>
      </>
    ),
  },
  {
    title: "Test with a real transaction",
    desc: (
      <>
        Pick a sample in the inspector on the right, or paste your own with <code>+</code>. The <b>trace</b>{" "}
        shows live exactly how your rules route and decide it — allow or refuse.
      </>
    ),
    visual: (
      <div className="insp-mini">
        <div className="s">
          <div className="lbl">Incoming transaction</div>
          <div className="txpick"><span>xUSDC transfer</span><span className="plus">+</span></div>
        </div>
        <div className="s">
          <div className="lbl">Evaluation trace</div>
          <div className="trrow"><span>route if · xtokens::transfer</span><span className="ok">match</span></div>
          <div className="trrow"><span>quantity.amount lte 10.0</span><span className="ok">true</span></div>
        </div>
        <div className="s"><div className="final">✓ SIGN</div></div>
      </div>
    ),
  },
  {
    title: "Turn a test into a rule",
    desc: (
      <>
        Got a concrete example of what your agent does? <b>Convert to route</b> scaffolds the matching branch —
        Route If, Get Fields, Decision — straight from it. No manual wiring.
      </>
    ),
    visual: (
      <>
        <div className="txchip">{`{ actions: [ xtokens::transfer ] }`}</div>
        <div className="arrow">→</div>
        <div className="scaf">
          <span className="convbtn">→ route</span>
          <MiniNode color={V.tx} title="Route If" />
          <MiniNode color={V.allow} title="Decision" />
        </div>
      </>
    ),
  },
  {
    title: "Tune it, then commit",
    desc: (
      <>
        Adjust the rules — recipients, caps, cooldowns, on-chain lookups. When it’s right, <b>Commit</b> pushes{" "}
        <code>setpolicy</code> from your own wallet. The key never leaves the daemon.
      </>
    ),
    visual: (
      <>
        <MiniNode color={V.allow} title="Decision">
          <div className="seg"><span className="on">allow</span><span>deny</span></div>
          <div className="fldrow">max per tx · 1.0000 XPR</div>
        </MiniNode>
        <div className="arrow">→</div>
        <div className="commit">Commit policy on-chain →</div>
      </>
    ),
  },
];

export function EditorTour({ onClose }: { onClose: () => void }) {
  const [i, setI] = useState(0);
  const last = i === STEPS.length - 1;

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
      else if (e.key === "ArrowRight") setI((x) => Math.min(STEPS.length - 1, x + 1));
      else if (e.key === "ArrowLeft") setI((x) => Math.max(0, x - 1));
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  const step = STEPS[i];
  return (
    <div className="tourbg" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="tourcard" role="dialog" aria-modal="true" aria-label="Editor tour">
        <div className="viz">{step.visual}</div>
        <div className="tbody">
          <div className="tstep">Step {i + 1} of {STEPS.length}</div>
          <h2>{step.title}</h2>
          <p>{step.desc}</p>
        </div>
        <div className="tnav">
          <button className="tbtn skip" onClick={onClose}>Skip tour</button>
          <span className="grow" />
          <span className="dots">
            {STEPS.map((_, k) => <i key={k} className={k === i ? "on" : ""} />)}
          </span>
          {i > 0 && (
            <button className="tbtn" onClick={() => setI((x) => Math.max(0, x - 1))}>Back</button>
          )}
          <button
            className="tbtn primary"
            onClick={() => {
              if (last) onClose();
              else setI((x) => Math.min(STEPS.length - 1, x + 1));
            }}
          >
            {last ? "Start building" : "Next →"}
          </button>
        </div>
      </div>
    </div>
  );
}
