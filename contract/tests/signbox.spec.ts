import { expect } from "chai";
import { Blockchain, expectToThrow } from "@proton/vert";
import { Checksum256, Serializer } from "@greymass/eosio";
import { createHash } from "crypto";

/**
 * SignBox contract tests (spec §7).
 *
 * NOTE: these require a successful `npm run build` first (they load the
 * compiled WASM/ABI from target/). See BUILD.md for the pinned toolchain.
 */

const blockchain = new Blockchain();
const contract = blockchain.createContract("signbox", "target/signbox.contract");

beforeEach(async () => {
  blockchain.resetTables();
  await blockchain.createAccounts("superdev", "otherdev", "superagent", "otheragent");
});

/** sha256 of the canonical policy string, as a checksum256 hex — matches §8.6. */
function hashOf(policyJson: string): string {
  return createHash("sha256").update(Buffer.from(policyJson, "utf8")).digest("hex");
}

/** A minimal canonical (RFC 8785-shaped) empty policy. Keys already sorted. */
const EMPTY_POLICY = '{"chain":{"chainId":"' + "a".repeat(64) + '","name":"XPR"},"default":"deny","rules":[],"schemaVersion":1}';
const EMPTY_HASH = hashOf(EMPTY_POLICY);

const rows = () => contract.tables.policies().getTableRows();

describe("createpolicy", () => {
  it("creates a row authorized by the authority", async () => {
    await contract.actions
      .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
      .send("superdev@active");
    const row = rows()[0];
    expect(row.agent).to.equal("superagent");
    expect(row.authority).to.equal("superdev");
    expect(row.agentperm).to.equal("xp2vr3");
    expect(row.version).to.equal(1);
    expect(row.enabled).to.equal(1);
  });

  it("requires the authority signature", async () => {
    await expectToThrow(
      contract.actions
        .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
        .send("superagent@active"),
      "missing required authority superdev",
    );
  });

  it("rejects a hash that does not match the json", async () => {
    await expectToThrow(
      contract.actions
        .createpolicy(["superagent", "superdev", "xp2vr3", 1, "b".repeat(64), EMPTY_POLICY])
        .send("superdev@active"),
      "policy hash does not match the canonical policy json",
    );
  });

  it("rejects a non-existent agent account", async () => {
    await expectToThrow(
      contract.actions
        .createpolicy(["ghostagent11", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
        .send("superdev@active"),
      "agent account does not exist",
    );
  });

  it("rejects an initial version other than 1", async () => {
    await expectToThrow(
      contract.actions
        .createpolicy(["superagent", "superdev", "xp2vr3", 2, EMPTY_HASH, EMPTY_POLICY])
        .send("superdev@active"),
      "initial policy version must be 1",
    );
  });

  it("rejects a duplicate row", async () => {
    await contract.actions
      .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
      .send("superdev@active");
    await expectToThrow(
      contract.actions
        .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
        .send("superdev@active"),
      "a policy already exists for this agent",
    );
  });
});

describe("setpolicy", () => {
  const V2 = '{"chain":{"chainId":"' + "a".repeat(64) + '","name":"XPR"},"default":"deny","rules":[{"effect":"allow","id":"r1","match":{"contract":"eosio.token"}}],"schemaVersion":1}';
  const V2_HASH = hashOf(V2);

  beforeEach(async () => {
    await contract.actions
      .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
      .send("superdev@active");
  });

  it("updates with a strictly greater version", async () => {
    await contract.actions.setpolicy(["superagent", 2, V2_HASH, V2]).send("superdev@active");
    expect(rows()[0].version).to.equal(2);
  });

  it("rejects a non-increasing version (anti-rollback source)", async () => {
    await contract.actions.setpolicy(["superagent", 2, V2_HASH, V2]).send("superdev@active");
    await expectToThrow(
      contract.actions.setpolicy(["superagent", 2, V2_HASH, V2]).send("superdev@active"),
      "policy version must strictly increase",
    );
  });

  it("requires the row's authority", async () => {
    await expectToThrow(
      contract.actions.setpolicy(["superagent", 2, V2_HASH, V2]).send("otherdev@active"),
      "missing required authority superdev",
    );
  });
});

describe("disable / enable", () => {
  beforeEach(async () => {
    await contract.actions
      .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
      .send("superdev@active");
  });

  it("disables and re-enables under the authority", async () => {
    await contract.actions.disable(["superagent"]).send("superdev@active");
    expect(rows()[0].enabled).to.equal(0);
    await contract.actions.enable(["superagent"]).send("superdev@active");
    expect(rows()[0].enabled).to.equal(1);
  });

  it("rejects disable from a non-authority", async () => {
    await expectToThrow(
      contract.actions.disable(["superagent"]).send("otherdev@active"),
      "missing required authority superdev",
    );
  });
});

describe("setauthority", () => {
  beforeEach(async () => {
    await contract.actions
      .createpolicy(["superagent", "superdev", "xp2vr3", 1, EMPTY_HASH, EMPTY_POLICY])
      .send("superdev@active");
  });

  it("requires BOTH current and new authority (double acceptance)", async () => {
    // Missing the new authority's signature.
    await expectToThrow(
      contract.actions.setauthority(["superagent", "otherdev"]).send("superdev@active"),
      "missing required authority otherdev",
    );
    // Co-signed by both.
    await contract.actions
      .setauthority(["superagent", "otherdev"])
      .send(["superdev@active", "otherdev@active"]);
    expect(rows()[0].authority).to.equal("otherdev");
  });
});
