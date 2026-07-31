/**
 * Typed error hierarchy. Every error thrown inside the decision pipeline is
 * mapped to a deny decision (INV-010 — fail closed). Error messages must
 * never contain secret material (INV-002).
 */

export class SignBoxError extends Error {
  override readonly name: string = "SignBoxError";
}

/** Structural violation of an input or policy document. */
export class ValidationError extends SignBoxError {
  override readonly name = "ValidationError";
}

/** RFC 8785 canonicalization failure (unsupported value). */
export class CanonicalizationError extends SignBoxError {
  override readonly name = "CanonicalizationError";
}

/** Asset parsing/comparison failure (bad format, overflow, precision mismatch). */
export class AssetError extends SignBoxError {
  override readonly name = "AssetError";
}

/**
 * A value could not be compared unambiguously during policy evaluation
 * (e.g. precision mismatch, missing normalized field). Always resolves to
 * a deny (INV-010).
 */
export class AmbiguousValueError extends SignBoxError {
  override readonly name = "AmbiguousValueError";
}

/**
 * A deterministic async provider (INV-008-A) could not be resolved or its
 * evidence is missing/invalid. Always a refusal (fail closed) — a rule that
 * depends on unavailable external state must never silently pass.
 */
export class ProviderUnavailableError extends SignBoxError {
  override readonly name = "ProviderUnavailableError";
}

/** Keystore failure. The message never includes passphrases or key bytes. */
export class KeystoreError extends SignBoxError {
  override readonly name = "KeystoreError";
  constructor(
    readonly code:
      | "DECRYPT_FAILED"
      | "FILE_EXISTS"
      | "FILE_NOT_FOUND"
      | "BAD_FORMAT"
      | "UNSUPPORTED_VERSION"
      | "PERMISSIONS",
    message: string,
  ) {
    super(message);
  }
}
