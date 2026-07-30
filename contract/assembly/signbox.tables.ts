import { Name, Table, Checksum256, EMPTY_NAME } from "proton-tsc";

/**
 * One policy row per agent account (spec §7.1). The agent's real XPR account
 * name is the primary key (§7.2): the blockchain account IS the identity, so
 * no logical alias can be pre-empted.
 *
 * `policyjson` is stored in canonical JCS form and `policyhash` is its
 * sha256 (§8.6). The contract cannot parse or validate the JSON (§7.5) — it
 * only guarantees authorization, version monotonicity, integrity (hash
 * matches the stored bytes) and distribution. The daemon is the sole policy
 * validator.
 */
@table("policies")
export class PolicyRow extends Table {
  constructor(
    public agent: Name = EMPTY_NAME,
    public authority: Name = EMPTY_NAME,
    public agentperm: Name = EMPTY_NAME,
    public version: u32 = 0,
    public policyhash: Checksum256 = new Checksum256(),
    public policyjson: string = "",
    public enabled: bool = false,
    public createdat: u64 = 0,
    public updatedat: u64 = 0,
  ) {
    super();
  }

  @primary
  get primary(): u64 {
    return this.agent.N;
  }
}
