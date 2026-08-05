/**
 * The policy schema's closed vocabularies (spec §8) — string patterns shared
 * VERBATIM between the daemon's validator (schema.ts) and the web editor's
 * compiler, so the editor can never produce a path the daemon rejects as
 * schema_invalid, and neither side keeps a hand-copied regex (#45).
 *
 * PURE module: no imports, no Node APIs — safe for the browser bundle.
 *
 * Note: `authorization.actor|permission` and the 64-hex chain id are the XPR
 * dialect's vocabulary; the PolicyDialect extraction (#45 phase A) moves them
 * behind the chain module. Keeping them here keeps daemon/web in lockstep in
 * the meantime.
 */

/** Match paths are a closed vocabulary — unknown paths are schema errors. */
export const MATCH_PATH_PATTERN =
  "^(contract|action|authorization\\.(actor|permission)|data\\.[a-zA-Z0-9_]{1,64}(\\.[a-zA-Z0-9_]{1,64}){0,4})$";

/** Provider `select` field names (spec §8.4). */
export const SELECT_FIELD_PATTERN = "^[a-zA-Z0-9_]{1,64}$";

/** Rule ids. */
export const RULE_ID_PATTERN = "^[a-z0-9][a-z0-9-]{0,63}$";

/** Chain ids (Antelope 64-hex today — see the dialect note above). */
export const CHAIN_ID_PATTERN = "^[0-9a-f]{64}$";

export const MATCH_PATH_RE = new RegExp(MATCH_PATH_PATTERN);
export const SELECT_FIELD_RE = new RegExp(SELECT_FIELD_PATTERN);
export const RULE_ID_RE = new RegExp(RULE_ID_PATTERN);
export const CHAIN_ID_RE = new RegExp(CHAIN_ID_PATTERN);
