/**
 * Static chain registration — importing this module makes every built-in
 * chain resolvable through `getChain(name)`. Adding a chain = one directory
 * under src/chains/ plus one registerChain line here (issue #44).
 */

import { registerChain, getChain, registeredChains } from "./registry.js";
import { xprModule } from "./xpr/module.js";

registerChain(xprModule);

export { getChain, registeredChains };
export type { ChainModule, ChainWiring, PrivateKeyProvider, ChainKeyPair } from "./registry.js";
