/**
 * @proton/js SignatureProvider backed by a KeystoreBackend (#46).
 *
 * Replaces JsSignatureProvider: instead of holding the WIF in-process, it
 * computes the Antelope signing digest and asks the backend to sign it —
 * the private key never crosses the keystore boundary. The backend returns
 * the chain-neutral `[recoveryId, r, s]` layout; this provider adds the
 * Antelope header byte and the SIG_K1 encoding.
 */

import { Numeric } from "@proton/js";
import { createHash } from "node:crypto";
import type { KeystoreBackend } from "../../keystore/backend.js";

interface SignatureProviderArgs {
  chainId: string;
  requiredKeys: string[];
  serializedTransaction: Uint8Array;
  serializedContextFreeData?: Uint8Array;
}

interface PushTransactionArgs {
  signatures: string[];
  serializedTransaction: Uint8Array;
  serializedContextFreeData?: Uint8Array;
}

export class KeystoreSignatureProvider {
  constructor(
    private readonly keystore: KeystoreBackend,
    private readonly keyId: string,
    private readonly publicKey: string,
  ) {}

  async getAvailableKeys(): Promise<string[]> {
    return [this.publicKey];
  }

  async sign(args: SignatureProviderArgs): Promise<PushTransactionArgs> {
    // The Antelope signing digest: sha256(chainId ‖ packed_trx ‖ cfd-hash|zero32).
    const digest = createHash("sha256")
      .update(Buffer.from(args.chainId, "hex"))
      .update(Buffer.from(args.serializedTransaction))
      .update(
        args.serializedContextFreeData !== undefined && args.serializedContextFreeData.length > 0
          ? createHash("sha256").update(Buffer.from(args.serializedContextFreeData)).digest()
          : Buffer.alloc(32),
      )
      .digest();

    const recovered = await this.keystore.signDigest(this.keyId, digest, "secp256k1-canonical");
    // [recid, r, s] → Antelope layout [header = 27 + compressed(4) + recid, r, s]
    const sigData = new Uint8Array(65);
    sigData[0] = 27 + 4 + recovered[0]!;
    sigData.set(recovered.subarray(1), 1);
    const signature = Numeric.signatureToString({ type: Numeric.KeyType.k1, data: sigData });

    return {
      signatures: [signature],
      serializedTransaction: args.serializedTransaction,
      ...(args.serializedContextFreeData !== undefined
        ? { serializedContextFreeData: args.serializedContextFreeData }
        : {}),
    };
  }
}
