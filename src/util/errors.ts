import { KeyLike } from "jose"

/**
 * A generic Error that all other COSE specific Error subclasses extend.
 *
 * @example Checking thrown error is a COSE one
 *
 * ```js
 * if (err instanceof cose.errors.COSEError) {
 *   // ...
 * }
 * ```
 */
export class COSEError extends Error {
  /** A unique error code for the particular error subclass. */
  static get code(): string {
    return 'ERR_COSE_GENERIC'
  }

  /** A unique error code for the particular error subclass. */
  code: string = 'ERR_COSE_GENERIC'

  constructor(message?: string) {
    super(message)
    this.name = this.constructor.name
    // @ts-ignore
    Error.captureStackTrace?.(this, this.constructor)
  }
}

/**
 * An error subclass thrown when a JOSE Algorithm is not allowed per developer preference.
 *
 * @example Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_COSE_ALG_NOT_ALLOWED') {
 *   // ...
 * }
 * ```
 *
 * @example Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.JOSEAlgNotAllowed) {
 *   // ...
 * }
 * ```
 */
export class COSEAlgNotAllowed extends COSEError {
  static get code(): 'ERR_COSE_ALG_NOT_ALLOWED' {
    return 'ERR_COSE_ALG_NOT_ALLOWED'
  }

  code = 'ERR_COSE_ALG_NOT_ALLOWED'
}

/**
 * An error subclass thrown when a particular feature or algorithm is not supported by this
 * implementation or JOSE in general.
 *
 * @example Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_COSE_NOT_SUPPORTED') {
 *   // ...
 * }
 * ```
 *
 * @example Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.JOSENotSupported) {
 *   // ...
 * }
 * ```
 */
export class COSENotSupported extends COSEError {
  static get code(): 'ERR_COSE_NOT_SUPPORTED' {
    return 'ERR_COSE_NOT_SUPPORTED'
  }

  code = 'ERR_COSE_NOT_SUPPORTED'
}


/**
 * An error subclass thrown when a JWKS is invalid.
 *
 * @example Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_JWKS_INVALID') {
 *   // ...
 * }
 * ```
 *
 * @example Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.JWKSInvalid) {
 *   // ...
 * }
 * ```
 */
export class JWKSInvalid extends COSEError {
  static get code(): 'ERR_JWKS_INVALID' {
    return 'ERR_JWKS_INVALID'
  }

  code = 'ERR_JWKS_INVALID'
}

/**
 * An error subclass thrown when no keys match from a JWKS.
 *
 * @example Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_JWKS_NO_MATCHING_KEY') {
 *   // ...
 * }
 * ```
 *
 * @example Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.JWKSNoMatchingKey) {
 *   // ...
 * }
 * ```
 */
export class JWKSNoMatchingKey extends COSEError {
  static get code(): 'ERR_JWKS_NO_MATCHING_KEY' {
    return 'ERR_JWKS_NO_MATCHING_KEY'
  }

  code = 'ERR_JWKS_NO_MATCHING_KEY'

  message = 'no applicable key found in the JSON Web Key Set'
}

/**
 * An error subclass thrown when multiple keys match from a JWKS.
 *
 * @example Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_JWKS_MULTIPLE_MATCHING_KEYS') {
 *   // ...
 * }
 * ```
 *
 * @example Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.JWKSMultipleMatchingKeys) {
 *   // ...
 * }
 * ```
 */
export class JWKSMultipleMatchingKeys extends COSEError {
  /** @ignore */
  [Symbol.asyncIterator]!: () => AsyncIterableIterator<KeyLike>

  static get code(): 'ERR_JWKS_MULTIPLE_MATCHING_KEYS' {
    return 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'
  }

  code = 'ERR_JWKS_MULTIPLE_MATCHING_KEYS'

  message = 'multiple matching keys found in the JSON Web Key Set'
}

export class X509NoMatchingCertificate extends COSEError {
  static get code(): 'ERR_X509_NO_MATCHING_CERTIFICATE' {
    return 'ERR_X509_NO_MATCHING_CERTIFICATE'
  }

  code = 'ERR_X509_NO_MATCHING_CERTIFICATE'

  message = 'no applicable certificate found in the COSE headers'
}

export class X509InvalidCertificateChain extends COSEError {
  static get code(): 'ERR_X509_INVALID_CERTIFICATE_CHAIN' {
    return 'ERR_X509_INVALID_CERTIFICATE_CHAIN'
  }

  code = 'ERR_X509_INVALID_CERTIFICATE_CHAIN'
}


/**
 * An error subclass thrown when a COSE ciphertext decryption fails.
 *
 * @example
 *
 * Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_COSE_DECRYPTION_FAILED') {
 *   // ...
 * }
 * ```
 *
 * @example
 *
 * Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.COSEDecryptionFailed) {
 *   // ...
 * }
 * ```
 */
export class COSEDecryptionFailed extends COSEError {
  /** @ignore */
  static get code(): 'ERR_COSE_DECRYPTION_FAILED' {
    return 'ERR_COSE_DECRYPTION_FAILED'
  }

  code = 'ERR_COSE_DECRYPTION_FAILED'

  message = 'decryption operation failed'
}


/**
 * An error subclass thrown when an encrypted COSE is invalid.
 *
 * @example
 *
 * Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_COSE_ENCRYPTED_INVALID') {
 *   // ...
 * }
 * ```
 *
 * @example
 *
 * Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.COSEEncryptedInvalid) {
 *   // ...
 * }
 * ```
 */
export class COSEEncryptedInvalid extends COSEError {
  /** @ignore */
  static get code(): 'ERR_COSE_ENCRYPTED_INVALID' {
    return 'ERR_COSE_ENCRYPTED_INVALID'
  }

  code = 'ERR_COSE_ENCRYPTED_INVALID'
}

/**
 * An error subclass thrown when the COSE message is invalid.
 */
export class COSEInvalid extends COSEError {
  /** @ignore */
  static get code(): 'ERR_COSE_INVALID' {
    return 'ERR_COSE_INVALID'
  }

  code = 'ERR_COSE_INVALID'
}

/**
 * An error subclass thrown when COSE signature verification fails.
 *
 * @example Checking thrown error is this one using a stable error code
 *
 * ```js
 * if (err.code === 'ERR_COSE_SIGNATURE_VERIFICATION_FAILED') {
 *   // ...
 * }
 * ```
 *
 * @example Checking thrown error is this one using `instanceof`
 *
 * ```js
 * if (err instanceof jose.errors.COSESignatureVerificationFailed) {
 *   // ...
 * }
 * ```
 */
export class COSESignatureVerificationFailed extends COSEError {
  static get code(): 'ERR_COSE_SIGNATURE_VERIFICATION_FAILED' {
    return 'ERR_COSE_SIGNATURE_VERIFICATION_FAILED'
  }

  code = 'ERR_COSE_SIGNATURE_VERIFICATION_FAILED'

  message = 'signature verification failed'
}
