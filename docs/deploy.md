# Release deployment

A `release/x.x.x` **tag** builds, tests, and ships both the CLI and the web
front-end via `.github/workflows/deploy.yml`.

```bash
# cut a release
git tag release/1.2.3
git push origin release/1.2.3
```

The tag's version (`1.2.3`) is stamped into `package.json`, so on the server
`signbox --version` prints `1.2.3`.

## What the workflow does

| Job | Steps |
|-----|-------|
| **cli** | `npm ci` → stamp version → build → **test** → `npm pack` → attach the tarball to the GitHub Release → scp it to the server → `npm install -g` |
| **web** | tar the `web/` source → scp to the server → `docker compose up -d --build` |

## Secrets & variables

In **Settings → Secrets and variables → Actions** (same names as the `railgun`
project):

| Secret | Value |
|--------|-------|
| `DEPLOY_HOST` | server hostname or IP |
| `DEPLOY_USER` | the deploy user (the one that runs the daemon + containers) |
| `DEPLOY_SSH_KEY` | the private key already stored in GitHub |

| Variable | Default | Value |
|----------|---------|-------|
| `DEPLOY_PORT` | `22` | SSH port |
| `DEPLOY_PATH` | `~/signbox` | base dir on the server (web lands in `$DEPLOY_PATH/web`) |

You can also deploy manually from the **Actions** tab (`workflow_dispatch`),
optionally passing a `ref` like `release/1.2.3`.

## Why it won't clash with your other containers

The web is **stateless** (no volumes). The compose file (`web/docker-compose.yml`)
is scoped so it only ever touches its own container:

- `name: signbox` → its own compose project and **isolated network**;
- `container_name: signbox-web` → a dedicated name, cleanly replaced on each `up -d`;
- `127.0.0.1:8085:80` → bound to **localhost only** — no public port, no clash.

`docker compose up -d --build` rebuilds and replaces **only** `signbox-web`; every
other container/network is untouched. If `8085` is already taken, change it in
`web/docker-compose.yml` (and the proxy config below).

## Route the domain to it

Your edge proxy (nginx **or** Caddy) fronts `signbox.rockerone.io` and proxies to
`127.0.0.1:8085`.

**Caddy** (`Caddyfile`) — automatic HTTPS:

```caddy
signbox.rockerone.io {
    reverse_proxy 127.0.0.1:8085
}
```

**nginx** (server block, TLS via certbot):

```nginx
server {
    server_name signbox.rockerone.io;

    location / {
        proxy_pass http://127.0.0.1:8085;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
    # listen 443 ssl; ... (managed by certbot)
}
```

The SPA does client-side routing; nginx inside the container already falls back
to `index.html`, so deep links (`/my-agents`, `/getting-started`) work on refresh.

## After a CLI release: restart the daemon manually

`npm install -g` updates the `signbox` binary, but the **running daemon keeps the
old code** until restarted — and a restart needs the keystore passphrase, so the
workflow does NOT do it for you:

```bash
signbox daemon restart   # you enter the passphrase
```

> If `npm install -g` needs elevated rights on your box, run the daemon user with
> a user-level Node (nvm) or prefix the install with `sudo` in the workflow.
