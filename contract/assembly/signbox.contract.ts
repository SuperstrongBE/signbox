import {
  Name,
  Contract,
  TableStore,
  Checksum256,
  check,
  requireAuth,
  isAccount,
  currentTimeMs,
  sha256,
  Utils,
} from "proton-tsc";
import { PolicyRow } from "./signbox.tables";

/**
 * SignBox central policy contract (spec §7).
 *
 * Source of truth for every agent's policy. It enforces exactly four things
 * (spec §7.5):
 *  - authorization: only the registered authority can mutate a row;
 *  - monotonicity: `version` can only strictly increase;
 *  - integrity: sha256(policyjson) must equal policyhash — verifiable here
 *    because policyjson is required to already be in canonical JCS form;
 *  - distribution: a single public, deterministic state per agent.
 *
 * It deliberately does NOT parse or validate the policy JSON — that is the
 * daemon's job (§7.5). RAM for every row is paid by the authority (the payer
 * passed to set/update), per the project decision that the superior
 * authority funds the agent.
 */

/** Low size cap for v0.1 (spec §7.4): authority pays RAM, so bound it hard. */
const MAX_POLICY_BYTES: i32 = 16384;

@contract
export class SignboxContract extends Contract {
  policies: TableStore<PolicyRow> = new TableStore<PolicyRow>(this.receiver);

  /**
   * Create the initial row for an agent. The initial policy is whatever the
   * authority submits (the contract cannot check "emptiness"); by convention
   * the onboarding flow submits an empty deny-all policy (§10.2).
   *
   * BOTH the authority and the agent must sign. Rows are first-come, with no
   * delete action, so requiring only the authority would let anyone front-run
   * an agent's onboarding and become its permanent policy authority (allow-all
   * or a permanent kill-switch). The agent's co-signature binds the row to a
   * consenting agent account. The ESR onboarding flow already controls the
   * agent account's `owner`/`active` in the same transaction, so it co-signs.
   */
  @action("createpolicy")
  createpolicy(
    agent: Name,
    authority: Name,
    agentperm: Name,
    version: u32,
    policyhash: Checksum256,
    policyjson: string,
  ): void {
    // isAccount(agent) is checked before requireAuth(agent) so a non-existent
    // agent yields the precise "does not exist" reason, not a missing-auth one.
    check(isAccount(agent), "agent account does not exist");
    requireAuth(authority);
    requireAuth(agent);
    check(isAccount(authority), "authority account does not exist");
    check(this.policies.get(agent.N) == null, "a policy already exists for this agent");
    check(version == 1, "initial policy version must be 1");
    this.assertPolicyIntegrity(policyjson, policyhash);

    const now = currentTimeMs();
    const row = new PolicyRow(
      agent,
      authority,
      agentperm,
      version,
      policyhash,
      policyjson,
      true,
      now,
      now,
    );
    // Authority pays the RAM for the row.
    this.policies.store(row, authority);
  }

  /** Update the policy. Version must strictly increase (anti-rollback source). */
  @action("setpolicy")
  setpolicy(agent: Name, version: u32, policyhash: Checksum256, policyjson: string): void {
    const row = this.policies.requireGet(agent.N, "no policy for this agent");
    requireAuth(row.authority);
    check(version > row.version, "policy version must strictly increase");
    this.assertPolicyIntegrity(policyjson, policyhash);

    row.version = version;
    row.policyhash = policyhash;
    row.policyjson = policyjson;
    row.updatedat = currentTimeMs();
    this.policies.update(row, row.authority);
  }

  /** Immediately disable all signing for the agent (kill-switch source). */
  @action("disable")
  disable(agent: Name): void {
    const row = this.policies.requireGet(agent.N, "no policy for this agent");
    requireAuth(row.authority);
    row.enabled = false;
    row.updatedat = currentTimeMs();
    this.policies.update(row, row.authority);
  }

  /** Re-enable a previously disabled policy. */
  @action("enable")
  enable(agent: Name): void {
    const row = this.policies.requireGet(agent.N, "no policy for this agent");
    requireAuth(row.authority);
    row.enabled = true;
    row.updatedat = currentTimeMs();
    this.policies.update(row, row.authority);
  }

  /** Update the dedicated permission name after a rotation/reconfiguration. */
  @action("setperm")
  setperm(agent: Name, agentperm: Name): void {
    const row = this.policies.requireGet(agent.N, "no policy for this agent");
    requireAuth(row.authority);
    row.agentperm = agentperm;
    row.updatedat = currentTimeMs();
    this.policies.update(row, row.authority);
  }

  /**
   * Exceptional authority transfer (spec §7.3). Requires BOTH the current and
   * the new authority to sign — a single co-signed transaction is the safe
   * double-acceptance pattern, preventing transfer to a wrong/hostile account
   * that could never act.
   */
  @action("setauthority")
  setauthority(agent: Name, newauthority: Name): void {
    const row = this.policies.requireGet(agent.N, "no policy for this agent");
    requireAuth(row.authority);
    requireAuth(newauthority);
    check(isAccount(newauthority), "new authority account does not exist");
    check(newauthority != row.authority, "new authority must differ from the current one");
    row.authority = newauthority;
    row.updatedat = currentTimeMs();
    // The new authority now pays the RAM for the row.
    this.policies.update(row, newauthority);
  }

  private assertPolicyIntegrity(policyjson: string, policyhash: Checksum256): void {
    check(policyjson.length > 0, "policy json must not be empty");
    check(policyjson.length <= MAX_POLICY_BYTES, "policy json exceeds the maximum size");
    const computed = sha256(Utils.stringToU8Array(policyjson));
    check(
      Utils.bytesCmp(computed.data, policyhash.data) == 0,
      "policy hash does not match the canonical policy json",
    );
  }
}
