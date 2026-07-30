/**
 * @proton/signing-request ships `"type": "module"` with a CJS `main`
 * (require-based) and no `exports` map, so the bare specifier resolves to a
 * file that fails under Node ESM. We import the actual ESM build directly;
 * this maps its types to the package's published declarations.
 */
declare module "@proton/signing-request/lib/proton-signing-request.m.js" {
  export * from "@proton/signing-request";
}
