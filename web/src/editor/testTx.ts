/**
 * User-saved test transactions, per agent + chain + network.
 *
 * A test is a raw transaction JSON the user pastes ("what would happen if the
 * agent submitted THIS?"). It is validated before storage so a malformed paste
 * can never crash the simulator, and normalised into SampleAction[] for the
 * pure interpreter (`eval.ts`). Storage key: `signbox-<agent>-test-transactions`.
 */

import type { SampleAction, TestTx } from "./types";

export const TEST_CHAIN = "xpr";
const MAX_ACTIONS = 16;
const MAX_JSON_BYTES = 64 * 1024;

export function storageKey(agent: string): string {
  return `signbox-${agent}-test-transactions`;
}

function readAll(agent: string): TestTx[] {
  try {
    const raw = localStorage.getItem(storageKey(agent));
    if (raw === null) return [];
    const parsed: unknown = JSON.parse(raw);
    if (!Array.isArray(parsed)) return [];
    return parsed.filter(isTestTx);
  } catch {
    return [];
  }
}

function isTestTx(e: unknown): e is TestTx {
  return (
    e !== null &&
    typeof e === "object" &&
    typeof (e as TestTx).name === "string" &&
    typeof (e as TestTx).chain === "string" &&
    typeof (e as TestTx).network === "string"
  );
}

/** Tests for the current chain + network only (as required by the picker). */
export function loadTestTxs(agent: string, network: string): TestTx[] {
  return readAll(agent).filter((e) => e.chain === TEST_CHAIN && e.network === network);
}

/** Append (or replace a same-name/chain/network) entry, preserving other networks' tests. */
export function saveTestTx(agent: string, entry: TestTx): void {
  const all = readAll(agent);
  const idx = all.findIndex(
    (e) => e.name === entry.name && e.chain === entry.chain && e.network === entry.network,
  );
  if (idx >= 0) all[idx] = entry;
  else all.push(entry);
  localStorage.setItem(storageKey(agent), JSON.stringify(all));
}

export function deleteTestTx(agent: string, name: string, network: string): void {
  const all = readAll(agent).filter(
    (e) => !(e.name === name && e.chain === TEST_CHAIN && e.network === network),
  );
  localStorage.setItem(storageKey(agent), JSON.stringify(all));
}

export type ValidateResult = { ok: true; tx: unknown } | { ok: false; error: string };

/** Parse + shape-check a pasted transaction so it can never crash the simulator. */
export function validateTxJson(text: string): ValidateResult {
  if (text.length > MAX_JSON_BYTES) return { ok: false, error: "transaction JSON is too large" };
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    return { ok: false, error: "not valid JSON" };
  }
  const actions = extractActions(parsed);
  if (actions === null) return { ok: false, error: "expected a transaction with an `actions` array" };
  if (actions.length === 0) return { ok: false, error: "the transaction has no actions" };
  if (actions.length > MAX_ACTIONS) return { ok: false, error: `too many actions (max ${MAX_ACTIONS})` };
  for (let i = 0; i < actions.length; i++) {
    const o = actions[i];
    if (o === null || typeof o !== "object") return { ok: false, error: `action ${i + 1} is not an object` };
    const contract = (o as Record<string, unknown>).account ?? (o as Record<string, unknown>).contract;
    const name = (o as Record<string, unknown>).name ?? (o as Record<string, unknown>).action;
    if (typeof contract !== "string" || contract === "")
      return { ok: false, error: `action ${i + 1}: missing "account"` };
    if (typeof name !== "string" || name === "")
      return { ok: false, error: `action ${i + 1}: missing "name"` };
  }
  return { ok: true, tx: parsed };
}

function extractActions(tx: unknown): Record<string, unknown>[] | null {
  if (Array.isArray(tx)) return tx as Record<string, unknown>[];
  if (tx !== null && typeof tx === "object") {
    const actions = (tx as { actions?: unknown }).actions;
    if (Array.isArray(actions)) return actions as Record<string, unknown>[];
    // A bare single action object is accepted too.
    const o = tx as Record<string, unknown>;
    if (typeof (o.account ?? o.contract) === "string") return [o];
  }
  return null;
}

/** Normalise a validated tx into the simulator's SampleAction[] shape. */
export function txToSampleActions(tx: unknown): SampleAction[] {
  const actions = extractActions(tx) ?? [];
  return actions.map((a) => ({
    contract: String(a.account ?? a.contract ?? ""),
    action: String(a.name ?? a.action ?? ""),
    data: normalizeData((a.data ?? {}) as Record<string, unknown>),
  }));
}

function normalizeData(d: Record<string, unknown>): SampleAction["data"] {
  const q = d.quantity;
  let quantity = { amount: "", symbol: "" };
  if (typeof q === "string") {
    // Antelope asset strings look like "1.0000 XPR".
    const parts = q.trim().split(/\s+/);
    quantity = { amount: parts[0] ?? "", symbol: parts[1] ?? "" };
  } else if (q !== null && typeof q === "object") {
    const qo = q as Record<string, unknown>;
    quantity = { amount: String(qo.amount ?? ""), symbol: String(qo.symbol ?? "") };
  }
  return { ...d, from: String(d.from ?? ""), to: String(d.to ?? ""), quantity };
}
