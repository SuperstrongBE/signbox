# SignBox companion web — static SPA (Vite + React), served by Caddy, which
# also terminates TLS (automatic Let's Encrypt) on its own dedicated host.
# The app is 100% client-side: it reads the onboarding payload from the URL
# hash and talks to the user's wallet in the browser. No server, no secrets.

# --- build ---
FROM node:22-alpine AS build
WORKDIR /app
COPY package*.json ./
RUN npm ci
COPY . .
RUN npm run build

# --- serve (Caddy: static SPA + automatic HTTPS) ---
FROM caddy:2-alpine AS runtime
COPY Caddyfile /etc/caddy/Caddyfile
COPY --from=build /app/dist /srv
EXPOSE 80 443
# Caddy's default entrypoint runs `caddy run --config /etc/caddy/Caddyfile`.
