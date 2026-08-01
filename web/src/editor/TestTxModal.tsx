/**
 * Add a custom test transaction: a name and a raw transaction JSON. The JSON is
 * validated on save (parse + shape check) so a bad paste can never reach the
 * simulator. Saved to localStorage for the current agent + chain + network.
 */

import { useEffect, useState } from "react";
import { validateTxJson } from "./testTx";

const PLACEHOLDER = `{
  "actions": [
    {
      "account": "eosio.token",
      "name": "transfer",
      "authorization": [{ "actor": "myagent", "permission": "active" }],
      "data": { "from": "myagent", "to": "someone", "quantity": "1.0000 XPR", "memo": "" }
    }
  ]
}`;

export function TestTxModal({
  network,
  onSave,
  onClose,
}: {
  network: string;
  onSave: (name: string, tx: unknown) => void;
  onClose: () => void;
}) {
  const [name, setName] = useState("");
  const [json, setJson] = useState("");
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    const onKey = (e: KeyboardEvent) => {
      if (e.key === "Escape") onClose();
    };
    window.addEventListener("keydown", onKey);
    return () => window.removeEventListener("keydown", onKey);
  }, [onClose]);

  function save() {
    if (name.trim() === "") {
      setError("give the test a name");
      return;
    }
    const res = validateTxJson(json);
    if (!res.ok) {
      setError(res.error);
      return;
    }
    onSave(name.trim(), res.tx);
  }

  return (
    <div className="modalbg" onClick={(e) => { if (e.target === e.currentTarget) onClose(); }}>
      <div className="modal" role="dialog" aria-modal="true" aria-label="Add a test transaction">
        <div className="mh">
          <span>Add a test transaction</span>
          <button className="x" aria-label="close" onClick={onClose}>×</button>
        </div>
        <div className="mp">
          <div className="mlbl">Name — stored locally for {network} · chain xpr</div>
          <input
            className="ttinput"
            value={name}
            placeholder="e.g. send 1 XPR to a blacklisted account"
            onChange={(e) => { setName(e.target.value); setError(null); }}
          />

          <div className="mlbl mt">Transaction JSON — the raw unserialized tx (an `actions` array)</div>
          <textarea
            className="ttjson mono"
            value={json}
            spellCheck={false}
            placeholder={PLACEHOLDER}
            onChange={(e) => { setJson(e.target.value); setError(null); }}
          />

          {error !== null && <div className="mwarn">⚠ {error}</div>}
        </div>
        <div className="mf">
          <button className="ghostbtn" onClick={onClose}>Cancel</button>
          <button className="pushbtn" onClick={save}>Save test</button>
        </div>
      </div>
    </div>
  );
}
