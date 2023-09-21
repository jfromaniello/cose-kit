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
