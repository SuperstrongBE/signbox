/**
 * XprChainAdapter — path 1 runtime signing (spec §5.5).
 *
 * All blockchain mechanics (ABI resolution, serialization, TAPOS, digest,
 * signature) are DELEGATED to @proton/js, per the spec. SignBox's own
 * responsibilities here are exactly three:
 *
 *  1. the private key never enters this module at all: signatures come from
 *     the keystore backend through signDigest (#46) — @proton/js only ever
 *     sees a SignatureProvider that returns SIG_K1 strings;
 *  2. the object handed to the package is `DecodedTransaction.source` —
 *     the validated original JSON, byte-for-byte what the policy saw
 *     (INV-014: nothing mutated between decision and signing);
 *  3. after serialization, the produced bytes are deserialized back and
 *     compared against the source (ABI round-trip guard): if what the
 *     chain package encoded is not exactly what was validated, SignBox
 *     refuses to return the signature (INV-010).
 *
 * The chain ID is pinned in configuration (INV-009); it is passed to the
 * package explicitly and is part of every signature digest, so a signature
 * can never be valid on another chain.
 */

import { Api, JsonRpc } from "@proton/js";
import { createHash } from "node:crypto";
import { SignBoxError, ValidationError } from "../../core/errors.js";
import { canonicalize } from "../../core/canonical/jcs.js";
import { decodeXprTransaction } from "./decode.js";
import { KeystoreSignatureProvider } from "./signatureProvider.js";
import { verifiedRpc } from "./rpc.js";
import { XPR_CHAIN, XPR_NETWORKS } from "./networks.js";
import type { KeystoreBackend } from "../../keystore/backend.js";
import type {
  ChainAdapter,
  ChainContext,
  DecodedTransaction,
  KeyHandle,
  NetworkDescriptor,
  SignedTransactionResult,
  TransactionSigner,
} from "../../core/types.js";

/** Signing failed in a way that must refuse the request (INV-010). */
export class SigningError extends SignBoxError {
  override readonly name = "SigningError";
}

interface TaposHeader {
  expiration: string;
  ref_block_num: number;
  ref_block_prefix: number;
}

interface XprSourceTransaction {
  actions: {
    account: string;
    name: string;
    authorization: { actor: string; permission: string }[];
    data: Record<string, unknown>;
  }[];
}

export interface XprSignerOptions {
  endpoints: string[];
  chainId: string;
  /** Short by default: a signed-but-unpushed transaction dies quickly (§5.5). */
  expireSeconds?: number;
  /**
   * The keystore holding the agent keys. Signing goes through
   * `signDigest` — the private key never enters this module (#46).
   */
  keystore: KeystoreBackend;
  /** Test seam: fixed TAPOS header instead of an RPC lookup. */
  taposProvider?: (api: Api) => Promise<TaposHeader>;
  /** Test seam: customize the Api construction (e.g. preloaded ABIs). */
  apiFactory?: (key: KeyHandle, options: XprSignerOptions) => Api;
}

/**
 * INV-009 chain ID pinning. @proton/js derives the SIGNING chain id from
 * rpc.get_info() on every transact() — there is no constructor pin — so a
 * lying RPC could otherwise make us sign a digest valid on another chain
 * (§17.4 chain ID substitution). Wrapping get_info() puts every code path
 * (TAPOS and signing digest alike) behind the pinned value: any mismatch
 * refuses before a signature exists.
 */
export function pinChainId(rpc: JsonRpc, chainId: string): void {
  const originalGetInfo = rpc.get_info.bind(rpc);
  rpc.get_info = async () => {
    const info = await originalGetInfo();
    if (info.chain_id !== chainId) {
      throw new SigningError("RPC chain id does not match the pinned chain id");
    }
    return info;
  };
}

function defaultApiFactory(key: KeyHandle, options: XprSignerOptions): Api {
  const rpc = verifiedRpc(new JsonRpc(options.endpoints), { chainId: options.chainId });

  return new Api({
    rpc,
    // Signing is delegated to the keystore backend through signDigest —
    // no key material is ever handed to @proton/js (#46). Cast: the
    // package's SignatureProvider interface is not assignable under
    // exactOptionalPropertyTypes.
    signatureProvider: new KeystoreSignatureProvider(
      options.keystore,
      key.keyId,
      key.publicKey,
    ) as unknown as NonNullable<ConstructorParameters<typeof Api>[0]["signatureProvider"]>,
    // SignBox knows exactly which key signs: resolving "required keys"
    // locally removes an RPC dependency from the signing hot path.
    authorityProvider: {
      getRequiredKeys: async (args) => args.availableKeys,
    },
  });
}

/** sha256(chainId ‖ serializedTransaction ‖ 32 zero bytes) — the signed digest. */
function transactionDigest(chainId: string, serializedTransaction: Uint8Array): string {
  return createHash("sha256")
    .update(Buffer.from(chainId, "hex"))
    .update(Buffer.from(serializedTransaction))
    .update(Buffer.alloc(32))
    .digest("hex");
}

export class XprTransactionSigner implements TransactionSigner {
  private readonly options: XprSignerOptions & { expireSeconds: number };
  private readonly apis = new Map<string, Api>();

  constructor(options: XprSignerOptions) {
    this.options = { ...options, expireSeconds: options.expireSeconds ?? 60 };
  }

  private apiFor(key: KeyHandle): Api {
    const cached = this.apis.get(key.keyId);
    if (cached !== undefined) return cached;
    const factory = this.options.apiFactory ?? defaultApiFactory;
    const api = factory(key, this.options);
    this.apis.set(key.keyId, api);
    return api;
  }

  /** Drop the cached Api for a rotated/revoked key. */
  evict(keyId: string): void {
    this.apis.delete(keyId);
  }

  async sign(tx: DecodedTransaction, key: KeyHandle): Promise<SignedTransactionResult> {
    if (tx.source === undefined || tx.source === null) {
      throw new SigningError("transaction has no validated source to sign");
    }
    if (key.chain.chainId !== this.options.chainId) {
      throw new SigningError("key chain does not match the signer configuration");
    }
    const source = tx.source as XprSourceTransaction;
    const api = this.apiFor(key);

    // Serialize + sign, never broadcast (INV-011: push is a separate step).
    // The envelope (TAPOS + expiration) is SignBox's to build, never the
    // agent's: either resolved from the chain (blocksBehind) or injected
    // through the taposProvider seam.
    const tapos = this.options.taposProvider
      ? await this.options.taposProvider(api)
      : undefined;
    const result = (await api.transact(
      { actions: source.actions },
      tapos === undefined
        ? {
            broadcast: false,
            sign: true,
            blocksBehind: 3,
            expireSeconds: this.options.expireSeconds,
          }
        : { broadcast: false, sign: true, transactionHeader: tapos },
    )) as { signatures: string[]; serializedTransaction: Uint8Array };

    if (!Array.isArray(result.signatures) || result.signatures.length === 0) {
      throw new SigningError("signing produced no signature");
    }

    // ABI round-trip guard: decode the bytes we are about to vouch for and
    // require them to describe EXACTLY the validated source actions. A lying
    // or drifting ABI makes this fail, and failure means refusal.
    const roundTrip = (await api.deserializeTransactionWithActions(
      result.serializedTransaction,
    )) as { actions: XprSourceTransaction["actions"] };
    const produced = roundTrip.actions.map((action) => ({
      account: action.account,
      name: action.name,
      authorization: action.authorization,
      data: action.data as Record<string, unknown>,
    }));
    if (canonicalize(produced) !== canonicalize(source.actions)) {
      throw new SigningError("serialized transaction does not round-trip to the validated JSON");
    }

    const packedHex = Buffer.from(result.serializedTransaction).toString("hex");
    return {
      signature: result.signatures[0] as string,
      transactionDigest: transactionDigest(this.options.chainId, result.serializedTransaction),
      signedTransaction: {
        signatures: result.signatures,
        packedTransaction: packedHex,
        compression: 0,
      },
    };
  }
}

export class XprChainAdapter implements ChainAdapter {
  readonly chain = XPR_CHAIN;

  async listNetworks(): Promise<NetworkDescriptor[]> {
    return Object.values(XPR_NETWORKS);
  }

  async resolveChainId(network: string): Promise<string> {
    const descriptor = XPR_NETWORKS[network];
    if (descriptor === undefined) {
      throw new ValidationError(`unknown XPR network: ${network}`);
    }
    return descriptor.chainId;
  }

  async decodeTransaction(input: unknown, context: ChainContext): Promise<DecodedTransaction> {
    if (context.chain !== XPR_CHAIN) {
      throw new ValidationError(`XprChainAdapter cannot decode for chain: ${context.chain}`);
    }
    return decodeXprTransaction(input, context);
  }
}
