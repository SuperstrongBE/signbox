/**
 * Socket BIRTH permissions (#63, follow-up to #55).
 *
 * The final 0600 mode alone proves nothing: the old vulnerable sequence
 * (listen creates a permissive socket, chmod tightens it later) also ends at
 * 0600. These tests capture the mode the socket file is BORN with, before the
 * belt-and-suspenders chmod, by intercepting the daemon's chmodSync call and
 * stat-ing the socket at that exact point — after listen(), before chmod.
 * Run under a deliberately permissive parent umask (0o000), they fail against
 * the pre-#55 listen-then-chmod implementation and pass with listenWithMode's
 * restrictive-umask bind.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { mkdtempSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

const hoisted = vi.hoisted(() => ({
  /** path → mode the file had when the daemon called chmodSync on it. */
  bornModes: new Map<string, number>(),
}));

vi.mock("node:fs", async (importOriginal) => {
  const real = await importOriginal<typeof import("node:fs")>();
  return {
    ...real,
    default: real,
    chmodSync: ((path, mode) => {
      // The daemon chmods right after listen() — the file's CURRENT mode here
      // is the mode the socket was born with.
      const key = String(path);
      if (!hoisted.bornModes.has(key)) {
        hoisted.bornModes.set(key, real.statSync(path).mode);
      }
      return real.chmodSync(path, mode);
    }) as typeof real.chmodSync,
  };
});

import { SignBoxDaemon } from "../src/daemon/server.js";

function tempSocketPath(name: string): string {
  return join(mkdtempSync(join(tmpdir(), "signbox-sockmode-")), name);
}

function makeDaemon(cfg: {
  socketPath: string;
  adminSocketPath?: string;
  socketMode?: number;
}): SignBoxDaemon {
  return new SignBoxDaemon(cfg, {
    decode: () => {
      throw new Error("not used");
    },
    signer: {
      sign: async () => {
        throw new Error("not used");
      },
    },
  });
}

describe("daemon sockets are born restrictive (no listen→chmod TOCTOU window)", () => {
  let prevUmask: number;

  beforeEach(() => {
    hoisted.bornModes.clear();
    // A deliberately permissive parent umask: without listenWithMode's
    // restrictive bind, sockets would be born world-accessible.
    prevUmask = process.umask(0o000);
  });

  afterEach(() => {
    process.umask(prevUmask);
  });

  it("agent socket is born with no group/other bits (default 0600)", async () => {
    const socketPath = tempSocketPath("signbox.sock");
    const daemon = makeDaemon({ socketPath });
    await daemon.start();
    try {
      const born = hoisted.bornModes.get(socketPath);
      expect(born).toBeDefined();
      expect(born! & 0o077).toBe(0);
    } finally {
      await daemon.stop();
    }
  });

  it("agent socket is born no broader than a custom socketMode", async () => {
    const socketPath = tempSocketPath("signbox.sock");
    const daemon = makeDaemon({ socketPath, socketMode: 0o660 });
    await daemon.start();
    try {
      const born = hoisted.bornModes.get(socketPath)!;
      // No permission bit outside the requested mode.
      expect(born & 0o777 & ~0o660).toBe(0);
    } finally {
      await daemon.stop();
    }
  });

  it("admin socket is born 0600", async () => {
    const socketPath = tempSocketPath("signbox.sock");
    const adminSocketPath = tempSocketPath("signbox.admin.sock");
    const daemon = makeDaemon({ socketPath, adminSocketPath });
    await daemon.start();
    try {
      const born = hoisted.bornModes.get(adminSocketPath);
      expect(born).toBeDefined();
      expect(born! & 0o777).toBe(0o600);
    } finally {
      await daemon.stop();
    }
  });

  it("restores the previous process umask after a successful start", async () => {
    const daemon = makeDaemon({ socketPath: tempSocketPath("signbox.sock") });
    await daemon.start();
    try {
      // Read-without-changing: umask(x) returns the previous value.
      const current = process.umask(0o000);
      process.umask(current);
      expect(current).toBe(0o000);
    } finally {
      await daemon.stop();
    }
  });

  it("restores the previous process umask after a listen failure", async () => {
    // A socket path inside a nonexistent directory: existsSync passes, then
    // listen() itself fails — the finally path must still restore the umask.
    const daemon = makeDaemon({
      socketPath: join(tmpdir(), "signbox-sockmode-missing", "nope", "signbox.sock"),
    });
    await expect(daemon.start()).rejects.toThrow();
    const current = process.umask(0o000);
    process.umask(current);
    expect(current).toBe(0o000);
  });
});
