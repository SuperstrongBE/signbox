# Building & testing the SignBox contract

The contract is written for [`proton-tsc`](https://github.com/ProtonProtocol/proton-tsc)
(AssemblyScript → WASM) and tested with [`@proton/vert`](https://github.com/ProtonProtocol/vert).

```bash
cd contract
npm install
npm run build      # -> target/signbox.contract.wasm + .abi
npm test           # vert tests (require a successful build first)
```

## Toolchain

`proton-asc` ships its transform as an **uncompiled** `node_modules/proton-asc/index.ts`
that must be transpiled by `ts-node` at build time. This is sensitive to the
exact Node / `ts-node` / `typescript` versions. The known-good matrix (the one
used to build and deploy the Railgun XPR contracts on testnet and mainnet) is:

| Tool | Version |
|---|---|
| Node.js | 16.x (`engines: >=16`) |
| typescript | ^4.6.2 |
| ts-node | ^10.7.0 |
| @types/node | ^17.0.22 |
| @proton/vert | ^0.3.18 |

`package.json` here pins that matrix. `proton-tsc` is pinned to a `0.3.x` line
to match the contract source API (`TableStore.store`, `currentTimeMs`,
`Utils.stringToU8Array`, `sha256`).

### Known issue on newer environments

On Node ≥ 20 and/or TypeScript ≥ 5, `proton-asc` fails to load its own
transform (`Cannot use import statement outside a module` / `Unexpected
identifier 'range'`), because its internal `ts-node` registration does not pin
`module: commonjs` and does not clear the default `node_modules` ignore. This
is a `proton-asc` limitation, not a contract issue — the shipped `hello`
example fails identically. **Build with the pinned Node 16 toolchain above**
(e.g. `nvm use 16`), or the Proton contract Docker image.

## What the contract guarantees

See `assembly/signbox.contract.ts` and spec §7 / §7.5. In short: authorization
(only the registered authority mutates), version monotonicity (source of the
daemon's anti-rollback), on-chain integrity (`sha256(policyjson) == policyhash`,
verifiable because the JSON is stored in canonical JCS form), and distribution.
The contract never parses the policy JSON — the daemon is the sole validator.
