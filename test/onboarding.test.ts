import { describe, expect, it, beforeEach } from "vitest";
import { runOnboarding, OnboardingError } from "../src/onboarding/flow.js";
import { buildOnboardingActions } from "../src/onboarding/actions.js";
import { generatePermissionName } from "../src/onboarding/permission.js";
import type {
  BuiltRequest,
  OnboardingBackend,
  OnboardingDeps,
  OnboardingInput,
  VerificationResult,
} from "../src/onboarding/flow.js";
import type { KeystoreMetadata } from "../src/keystore/encryptedFile.js";
import type { ChainContext } from "../src/core/types.js";

const CHAIN_ID = "71ee83bcf52142d61019d95f9cc5427ba6a0d7ff8accd9e2088ae2abeaf3d3dd";
const CHAIN: ChainContext = { chain: "XPR", network: "testnet", chainId: CHAIN_ID };
const NOW = Date.parse("2026-07-30T12:00:00.000Z");

interface Recorder {
  events: string[];
  tempMeta?: KeystoreMetadata;
  built?: BuiltRequest;
}

class MockBackend implements OnboardingBackend {
  authorityOk = true;
  agentAccount = false;
  policyRow = false;
  confirmation: { txid: string } | null = { txid: "tx123" };
  verification: VerificationResult = { ok: true };
  buildThrows = false;

  constructor(private readonly rec: Recorder) {}

  async authorityExists(): Promise<boolean> {
    return this.authorityOk;
  }
  async agentAccountExists(): Promise<boolean> {
    return this.agentAccount;
  }
  async policyRowExists(): Promise<boolean> {
    return this.policyRow;
  }
  async buildRequest(): Promise<BuiltRequest> {
    if (this.buildThrows) throw new Error("esr build failed");
    this.rec.events.push("build");
    const built: BuiltRequest = { esrUri: "esr://gmABC", summary: [] };
    this.rec.built = built;
    return built;
  }
  async waitForConfirmation(): Promise<{ txid: string } | null> {
    this.rec.events.push("wait");
    return this.confirmation;
  }
  async verifyLanded(): Promise<VerificationResult> {
    this.rec.events.push("verify");
    return this.verification;
  }
}

function makeDeps(rec: Recorder, backend: MockBackend): OnboardingDeps {
  return {
    backend,
    generateKey: async () => {
      rec.events.push("keygen");
      return { wif: "PVT_K1_secret", publicKey: "PUB_K1_agentkey" };
    },
    getPassphrase: async () => Buffer.from("passphrase"),
    keystore: {
      createTemp: (_path, _secret, _pass, meta) => {
        rec.events.push("createTemp");
        rec.tempMeta = meta;
      },
      promote: () => rec.events.push("promote"),
      destroy: () => rec.events.push("destroy"),
    },
    present: (req) => {
      rec.events.push("present");
      rec.built = req;
    },
    now: () => NOW,
  };
}

function input(overrides?: Partial<OnboardingInput>): OnboardingInput {
  return {
    chain: CHAIN,
    authority: "superdev",
    agent: "superagent",
    permission: "sbxab12c3",
    mode: "create",
    exportPolicy: "non-exportable",
    keystorePath: "/tmp/agent.keystore.json",
    ramBytes: 4096,
    ...overrides,
  };
}

describe("onboarding flow — happy path", () => {
  let rec: Recorder;
  let backend: MockBackend;

  beforeEach(() => {
    rec = { events: [] };
    backend = new MockBackend(rec);
  });

  it("runs the phases in the §10.3 order and promotes only after verify", async () => {
    const result = await runOnboarding(input(), makeDeps(rec, backend));
    expect(rec.events).toEqual([
      "keygen",
      "createTemp", // temp container BEFORE the ESR
      "build",
      "present", // ESR shown to the authority
      "wait", // wait for confirmation
      "verify", // verify the landed state
      "promote", // activate the key ONLY now
    ]);
    expect(result.txid).toBe("tx123");
    expect(result.publicKey).toBe("PUB_K1_agentkey");
    expect(result.permission).toBe("sbxab12c3");
  });

  it("seals the temp container with the agent's authenticated metadata", async () => {
    await runOnboarding(input(), makeDeps(rec, backend));
    expect(rec.tempMeta).toMatchObject({
      publicKey: "PUB_K1_agentkey",
      agent: "superagent",
      permission: "sbxab12c3",
      exportPolicy: "non-exportable",
      chain: CHAIN,
    });
  });
});

describe("onboarding flow — fail closed (§10.3)", () => {
  let rec: Recorder;
  let backend: MockBackend;

  beforeEach(() => {
    rec = { events: [] };
    backend = new MockBackend(rec);
  });

  it("destroys the temp container and never promotes on timeout", async () => {
    backend.confirmation = null;
    await expect(runOnboarding(input(), makeDeps(rec, backend))).rejects.toThrowError(
      expect.objectContaining({ code: "TIMEOUT" }),
    );
    expect(rec.events).toContain("createTemp");
    expect(rec.events).toContain("destroy");
    expect(rec.events).not.toContain("promote");
  });

  it("destroys the temp container and never promotes on a verification mismatch", async () => {
    backend.verification = { ok: false, reason: "policy hash mismatch" };
    await expect(runOnboarding(input(), makeDeps(rec, backend))).rejects.toThrowError(
      expect.objectContaining({ code: "VERIFICATION_FAILED" }),
    );
    expect(rec.events).toContain("destroy");
    expect(rec.events).not.toContain("promote");
  });

  it("destroys the temp container if the ESR build fails", async () => {
    backend.buildThrows = true;
    await expect(runOnboarding(input(), makeDeps(rec, backend))).rejects.toThrow();
    expect(rec.events).toContain("createTemp");
    expect(rec.events).toContain("destroy");
  });

  it("refuses (before keygen) when the authority does not exist", async () => {
    backend.authorityOk = false;
    await expect(runOnboarding(input(), makeDeps(rec, backend))).rejects.toThrowError(
      expect.objectContaining({ code: "AUTHORITY_MISSING" }),
    );
    expect(rec.events).not.toContain("keygen");
    expect(rec.events).not.toContain("createTemp");
  });

  it("refuses when the agent account already exists (create mode)", async () => {
    backend.agentAccount = true;
    await expect(runOnboarding(input({ mode: "create" }), makeDeps(rec, backend))).rejects.toThrowError(
      expect.objectContaining({ code: "AGENT_EXISTS" }),
    );
  });

  it("refuses when the agent account is missing (existing mode)", async () => {
    backend.agentAccount = false;
    await expect(
      runOnboarding(input({ mode: "existing" }), makeDeps(rec, backend)),
    ).rejects.toThrowError(expect.objectContaining({ code: "AGENT_MISSING" }));
  });

  it("refuses when a policy row already exists", async () => {
    backend.policyRow = true;
    await expect(runOnboarding(input(), makeDeps(rec, backend))).rejects.toThrowError(
      expect.objectContaining({ code: "POLICY_EXISTS" }),
    );
  });
});

describe("onboarding actions (§10.2 step 7)", () => {
  const base = {
    authority: "superdev",
    agent: "superagent",
    permission: "active",
    agentPublicKey: "PUB_K1_agentkey",
    authorityPublicKey: "PUB_K1_authoritykey",
    signboxContract: "signbox",
    emptyPolicyJson: '{"schemaVersion":1}',
    emptyPolicyHash: "a".repeat(64),
  };

  // NOTE: updateauth is temporarily disabled (XPR blacklists it in signing
  // requests), so it is absent from the action set for now (see actions.ts).
  it("create mode builds newaccount, buyrambytes, createpolicy (updateauth disabled)", () => {
    const actions = buildOnboardingActions({ ...base, mode: "create", ramBytes: 4096 });
    expect(actions.map((a) => `${a.account}::${a.name}`)).toEqual([
      "eosio::newaccount",
      "eosio::buyrambytes",
      "signbox::createpolicy",
    ]);
    expect(actions.some((a) => a.name === "updateauth")).toBe(false);
  });

  it("existing mode builds only createpolicy (updateauth disabled)", () => {
    const actions = buildOnboardingActions({ ...base, mode: "existing" });
    expect(actions.map((a) => `${a.account}::${a.name}`)).toEqual(["signbox::createpolicy"]);
  });

  it("the authority pays RAM", () => {
    const actions = buildOnboardingActions({ ...base, mode: "create", ramBytes: 8192 });
    const buyram = actions.find((a) => a.name === "buyrambytes")!;
    expect(buyram.data).toMatchObject({ payer: "superdev", receiver: "superagent", bytes: 8192 });
    expect(buyram.authorization).toEqual([{ actor: "superdev", permission: "active" }]);
  });

  it("omits the RAM purchase when ramBytes is 0", () => {
    const actions = buildOnboardingActions({ ...base, mode: "create", ramBytes: 0 });
    expect(actions.some((a) => a.name === "buyrambytes")).toBe(false);
  });

  it("owner = the authority's key, active = the agent's key", () => {
    const actions = buildOnboardingActions({ ...base, mode: "create" });
    const newaccount = actions.find((a) => a.name === "newaccount")!;
    expect(newaccount.data["owner"]).toMatchObject({
      threshold: 1,
      keys: [{ key: "PUB_K1_authoritykey", weight: 1 }],
      accounts: [],
    });
    expect(newaccount.data["active"]).toMatchObject({
      threshold: 1,
      keys: [{ key: "PUB_K1_agentkey", weight: 1 }],
      accounts: [],
    });
  });

  it("does not use updateauth (agent key goes straight on active)", () => {
    const actions = buildOnboardingActions({ ...base, mode: "create" });
    expect(actions.some((a) => a.name === "updateauth")).toBe(false);
  });

  it("createpolicy registers version 1 with the empty policy and hash", () => {
    const actions = buildOnboardingActions({ ...base, mode: "create" });
    const createpolicy = actions.find((a) => a.name === "createpolicy")!;
    expect(createpolicy.data).toMatchObject({
      agent: "superagent",
      authority: "superdev",
      agentperm: "active",
      version: 1,
      policyhash: "a".repeat(64),
      policyjson: '{"schemaVersion":1}',
    });
    expect(createpolicy.authorization).toEqual([{ actor: "superdev", permission: "active" }]);
  });
});

describe("permission name generation", () => {
  it("produces a valid Antelope name with the sbx prefix", () => {
    for (let i = 0; i < 50; i++) {
      const name = generatePermissionName();
      expect(name).toMatch(/^sbx[a-z1-5]{6}$/);
      expect(name.length).toBeLessThanOrEqual(12);
    }
  });
});
