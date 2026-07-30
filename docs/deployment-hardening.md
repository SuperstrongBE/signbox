# SignBox deployment hardening

SignBox removes the private key from the agent's reach **by design**: the key
never enters the LLM's context, and the agent only ever receives a
signature-or-refusal (INV-002, INV-014). What SignBox *cannot* do for you is
secure the host it runs on. This guide covers that half.

## The division of responsibility

| SignBox guarantees | The OS/ops must guarantee |
|---|---|
| The key is never in the agent/LLM context | The daemon process's memory isn't readable by other processes |
| The agent's only capability is "ask to sign", gated by policy | The keystore **file** isn't readable by the agent's user |
| The keystore is encrypted (Argon2id + XChaCha20-Poly1305) | A strong passphrase, so the encrypted blob is uncrackable offline |
| Every decision is deterministic and fail-closed | The host isn't root-compromised |

The residual attack surface is a **classic server-hardening surface** — user
isolation, filesystem permissions, process isolation, patching. An autonomous
agent ("run on autopilot, do anything") is only as powerful as **its OS user**;
it does not become root by being autonomous. Privilege escalation still requires
a real exploit, which is the IT surface below — not something the agent gets for
free.

> One-line threat model: even a fully prompt-poisoned, fully autonomous agent
> cannot read a key it has no path to, and cannot move funds beyond what the
> policy allows. Everything else is host hygiene.

---

## 1. Keep the key process and the agent process apart

There are exactly two ways to reach the key on a running host:

- **Door 1 — read the keystore file.** You get an *encrypted blob*; you must
  brute-force the Argon2id passphrase (see §5). Blocked by file permissions + a
  strong passphrase.
- **Door 2 — read the daemon's process memory** (where the key is decrypted).
  Requires root, or `ptrace` on the same user (see §4). Blocked by user
  separation + ptrace hardening.

The goal of everything below is to make **both doors** a hard OS wall, so
security never depends on the agent behaving.

### Option A — isolate the agent (recommended, works today)

Run the **agent** inside a container / namespace that simply does **not mount**
the SignBox home. There is no filesystem tree to climb because the keystore does
not exist in the agent's view. Bind-mount **only the request socket** in.

```bash
# daemon runs on the host as user `signbox`, socket at /run/signbox/signbox.sock
podman run --rm \
  --user 1001:1001 \                       # same uid as `signbox` → may use the 0600 socket
  --read-only \
  -v /run/signbox/signbox.sock:/run/signbox/signbox.sock \
  -v /run/signbox/tokens/funagent.token:/run/signbox/tokens/funagent.token:ro \
  your-agent-image
```

The agent gets the socket (sign-or-refuse) and its own token — **nothing else**.
`~signbox/.signbox/keystores` is not in the container's mount namespace, so a
`cat ../../keystores/*.json`, no matter how the LLM is poisoned, resolves to
nothing.

### Option B — separate OS users on one host

```
daemon → user `signbox`    keystore dir 0700, owned by signbox
agent  → user `agent`      cannot even list ~signbox/.signbox
```

An agent process climbing the tree hits **`EACCES`** at `~signbox/.signbox/` —
it cannot list the directory, let alone read the blob. The only bridge is the
socket.

> **Current limitation:** the request socket is chmod'd `0600` (daemon user
> only), so a *different* user cannot connect to it yet. Cross-user access needs
> a group-shared socket (`0660` + a shared `signbox-agents` group), which is a
> small config addition (`socketMode` / socket group) — tracked as a follow-up.
> Until then, prefer **Option A** (same uid, filesystem hidden by the container).

---

## 2. Filesystem permissions

Relocate the SignBox state out of a home directory so `ProtectHome=yes` (see §4)
can apply, and lock it down:

```jsonc
// ~signbox/.signbox/config.json  (or pass --config)
{
  "baseDir": "/var/lib/signbox"
}
```

```bash
sudo useradd --system --home-dir /var/lib/signbox --shell /usr/sbin/nologin signbox
sudo install -d -o signbox -g signbox -m 0700 /var/lib/signbox
sudo install -d -o signbox -g signbox -m 0700 /var/lib/signbox/keystores
# keystore files are written 0600 by SignBox; verify:
sudo -u signbox ls -l /var/lib/signbox/keystores   # -rw------- signbox signbox
```

| Path | Mode | Holds |
|---|---|---|
| `/var/lib/signbox` | `0700` | base dir |
| `…/keystores/*.keystore.json` | `0600` | encrypted key (Argon2id + XChaCha20) |
| `…/tokens/*.token` | `0600` | rotating local auth token (§12.3) |
| `…/state.db` | `0600` | quota journal + policy cache + audit |
| request socket | `0600` | sign requests (daemon user only, today) |
| admin socket | `0600` | kill-switch / status (daemon user only) |

---

## 3. The socket is the only bridge

- The **request socket** carries sign-or-refuse. It is the agent's *entire*
  capability. Never expose it over TCP or a network — keep it a Unix socket on
  the host (or bind-mounted into the agent's container).
- The **admin socket** (kill-switch, status) is always `0600` — daemon user
  only. Do not widen it.
- Each request carries the agent's rotating **local token** (`0600`), compared
  in constant time. A native `SO_PEERCRED`/`getpeereid` peer-credential check is
  planned as an additional layer (Phase 2 hardening).

---

## 4. Lock down the daemon with systemd

```ini
# /etc/systemd/system/signbox.service
[Unit]
Description=SignBox signing daemon
After=network-online.target
Wants=network-online.target

[Service]
User=signbox
Group=signbox
ExecStart=/usr/bin/signbox daemon start --config /var/lib/signbox/config.json
Restart=on-failure

# --- filesystem ---
ProtectHome=yes
ProtectSystem=strict
ReadWritePaths=/var/lib/signbox
RuntimeDirectory=signbox            # /run/signbox for the sockets, 0700
PrivateTmp=yes
PrivateDevices=yes

# --- privileges ---
NoNewPrivileges=yes
CapabilityBoundingSet=              # drop all capabilities
AmbientCapabilities=
RestrictSUIDSGID=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
RestrictRealtime=yes

# --- network: outbound HTTPS to chain RPC + Unix sockets only ---
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
IPAddressAllow=any                  # tighten to your RPC endpoints if you can
```

> The daemon needs **outbound** network for chain RPC reads and for the
> daemon-owned broadcast path (`sign --push`, §13). It never needs to *listen*
> on a network socket.

**Unattended restart caveat:** `signbox daemon start` prompts for the keystore
passphrase on a TTY, so a bare `systemctl restart` cannot auto-unlock. For
unattended hosts, unlock interactively once (e.g. `systemd-run --pty`), or feed
the passphrase from a secrets manager / `systemd` credential — a passphrase
source abstraction is a natural follow-up. **Do not** bake the passphrase into
the unit file or an env var in plaintext.

---

## 5. Block process-memory reads (ptrace)

Door 2 — reading the daemon's decrypted key from memory — is blocked for other
users by user separation, and for the *same* user by ptrace scope:

```ini
# /etc/sysctl.d/10-ptrace.conf
kernel.yama.ptrace_scope = 2     # only root may ptrace; 3 = nobody (needs reboot to lift)
```

```bash
sudo sysctl --system
```

Combined with §1, the in-memory key is unreachable without root — and root
compromise is the "classic server" line beyond which no hot-wallet design
survives.

---

## 6. Passphrase hygiene

The keystore is derived with **Argon2id** (`OPSLIMIT_MODERATE` = 3 passes,
`MEMLIMIT_MODERATE` = **256 MiB per guess**) and sealed with
XChaCha20-Poly1305. Argon2id is *memory-hard*: each guess costs 256 MiB of RAM,
which is what defeats GPU/ASIC cracking farms.

- Use a **high-entropy passphrase** (e.g. 6+ random words / a generated 20+ char
  secret). This is the single knob that decides whether a stolen keystore blob
  is crackable. Everything above assumes it is not.
- Keep the key **`non-exportable`** (the onboarding default): SignBox will not
  hand out the raw key via any API. This is defense-in-depth, not the barrier —
  it does not stop someone who has both the file *and* the passphrase.

---

## 7. Autonomous agents ("Claude/Codex on autopilot")

This is the scenario worth stating plainly: you let an agent run unattended with
broad tools ("do anything"). What holds:

- **"Access to everything" = everything its OS user can reach.** Autonomy is not
  privilege. If the agent runs as `agent` (Option B) or in a container
  (Option A), the keystore is simply not in reach — no prompt changes that.
- **Never run a funds-touching autonomous agent as the daemon's user with a
  shell.** That collapses the two doors into one process. Give it the socket and
  its token, nothing on the daemon's filesystem.
- **The policy is the ceiling.** For a fully-compromised agent, the worst case
  is "spend up to what the policy allows." Design the policy as if the agent is
  hostile, because autonomy means you can't assume otherwise.
- **Put anything that must be absolute on-chain** (§8, INV-006): local quotas
  are best-effort; chain-enforced permissions/`linkauth` are not.

---

## 8. On-chain backstop (and the current caveat)

Even a leaked key is bounded by what the chain enforces independently of SignBox
(INV-006): account permissions, thresholds, `linkauth`, absolute caps in a
contract. These are strictly stronger than SignBox's local quota.

> **Current caveat:** onboarding places the agent key on the account's `active`
> permission (XPR blacklists `eosio::updateauth` in signing requests, so a
> dedicated child permission isn't created yet). The chain-level second barrier
> is therefore weaker today. Adding a WebAuth/`linkauth`-based dedicated
> permission — so the key is chain-limited to specific actions — is the planned
> path to a true double barrier.

---

## Checklist

- [ ] Daemon and agent are **different OS users**, or the agent runs in a
      container that does not mount the SignBox home.
- [ ] `baseDir` relocated to `/var/lib/signbox`, `0700`, owned by `signbox`.
- [ ] Keystore/token/state files verified `0600`.
- [ ] Agent reaches **only** the request socket (+ its own token) — never the
      keystore path, never the admin socket.
- [ ] systemd unit hardened (`NoNewPrivileges`, `ProtectSystem=strict`,
      `ProtectHome`, dropped capabilities).
- [ ] `kernel.yama.ptrace_scope >= 2`.
- [ ] High-entropy keystore passphrase; not stored in plaintext anywhere.
- [ ] Policy written as if the agent is hostile; absolute limits pushed on-chain.
