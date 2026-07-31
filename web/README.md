# SignBox companion web app

The authority-signing surface. A headless CLI cannot open a Proton wallet
session (the Web SDK is browser-only, and the wallet requires a login before
signing). This small static app does exactly that: it reads an onboarding
request from the URL, opens a wallet session, and lets the authority sign.

Trust model: this app **never sees any key**. It only relays the transaction
the CLI built to the authority's own wallet. The full actions travel in the
URL **hash fragment** (client-side only, never sent to a server), so the app
signs exactly what the CLI intended — and the CLI still verifies the landed
result on-chain before it activates the agent key.

## Run locally

```bash
cd web
npm install
npm run dev        # http://localhost:5173
```

Then run the CLI and open the printed companion link:

```bash
signbox agent create            # prints an http://localhost:5173/#… link
```

Point at a different host with `signbox agent create --companion-url https://…`.

## Build (static)

```bash
npm run build      # -> web/dist, deployable to any static host
```

## Docker

A multi-stage `Dockerfile` builds the SPA and serves it with nginx (SPA
fallback, gzip, immutable caching for hashed assets). It's fully static — no
server, no secrets.

```bash
cd web
docker build -t signbox-companion .
docker run --rm -p 5173:80 signbox-companion   # http://localhost:5173
```

Then point the CLI at it:

```bash
signbox agent create --companion-url http://localhost:5173
```

For a public host, put it behind TLS (Caddy/Traefik/your load balancer) and use
`--companion-url https://your-host`. The onboarding payload travels in the URL
**hash**, so it never reaches the server or its logs.

## Flow

1. The CLI encodes the onboarding actions + a summary into the URL hash.
2. This app decodes it, shows the summary, and stores it in `localStorage`.
3. "Connect wallet" opens the Proton wallet session (login).
4. It checks you connected as the **authority** account.
5. "Sign & create agent" calls `session.transact({ actions })` — the wallet
   signs and broadcasts.
6. The CLI, still polling the chain, confirms the result and activates the key.

The same surface will host the policy editor (spec §11.4).
