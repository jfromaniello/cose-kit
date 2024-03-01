import { SignatureBase, VerifyOptions } from './SignatureBase.js';
import { COSEBase } from './COSEBase.js';
import { KeyLike } from 'jose';
import { COSEVerifyGetKey } from '../jwks/local.js';
import { UnprotectedHeaders, ProtectedHeaders, AlgorithmNames, Headers, Algorithms } from '../headers.js';
import sign from '#runtime/sign.js';
import { encoder, addExtension } from '../cbor.js';
import { decode } from './decode.js';
import * as errors from "../util/errors.js";

/**
 * Decoded COSE_Sign structure.
 */
export class Sign extends COSEBase {
  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    unprotectedHeaders: Map<number, unknown>,
    public readonly payload: Uint8Array,
    public readonly signatures: Signature[]) {
    super(protectedHeaders, unprotectedHeaders);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.signatures.map((signature) => [
        signature.protectedHeaders,
        signature.unprotectedHeaders,
        signature.signature
      ]),
    ];
  }

  /**
   *
   * Verifies the signature of this instance using the given key of a single recipient.
   *
   * @param key {KeyLike | Uint8Array | COSEVerifyGetKey} - The key to verify the signature with.
   * @param options {VerifyOptions} - Verify options
   * @param options.algorithms {Algorithms[]} - List of allowed algorithms
   * @param options.externalAAD {Uint8Array} - External Additional Associated Data
   * @param options.detachedPayload {Uint8Array} - The detached payload to verify the signature with.
   * @returns {Promise<void>}
   */
  public async verify(
    key: KeyLike | Uint8Array | COSEVerifyGetKey,
    options?: VerifyOptions,
  ): Promise<void> {
    for (const signature of this.signatures) {
      try {
        await signature.verify(key, this.encodedProtectedHeaders, this.payload, options);
        return;
      } catch (err) { /* empty */ }
    }

    throw new errors.COSESignatureVerificationFailed();
  }

  public async verifyX509(
    roots: string[],
    options?: VerifyOptions,
  ): Promise<void> {
    for (const signature of this.signatures) {
      try {
        const { publicKey } = await signature.verifyX509Chain(roots);
        await signature.verify(publicKey, this.encodedProtectedHeaders, this.payload, options);
        return;
      } catch (err) { /* empty */ }
    }
    throw new errors.COSESignatureVerificationFailed();
  }

  static async sign(
    bodyProtectedHeader: ProtectedHeaders | ConstructorParameters<typeof ProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined,
    payload: Uint8Array,
    signers: {
      key: KeyLike | Uint8Array,
      protectedHeaders: ProtectedHeaders,
      unprotectedHeaders?: UnprotectedHeaders,
    }[],
  ): Promise<Sign> {
    const encodedProtectedHeaders = ProtectedHeaders.from(bodyProtectedHeader).encode();
    const unprotectedHeadersMap = UnprotectedHeaders.from(unprotectedHeaders).esMap;
    const signatures = await Promise.all(signers.map(async ({ key, protectedHeaders, unprotectedHeaders }) => {
      return Signature.sign(
        encodedProtectedHeaders,
        protectedHeaders,
        unprotectedHeaders,
        payload,
        key,
      );
    }));
    return new Sign(
      encodedProtectedHeaders,
      unprotectedHeadersMap,
      payload,
      signatures,
    );
  }

  /**
  *
  * Decode a COSE_Sign structure from a buffer.
  *
  * @param cose {Uint8Array} - The buffer containing the Cose Sign tagged or untagged message.
  * @returns {Sign} - The decoded COSE_Sign structure.
  */
  static decode(cose: Uint8Array): Sign {
    return decode(cose, Sign);
  }

  static tag = 98;
}

/**
 * This class represent a single signature inside a COSE_Sign structure.
 */
export class Signature extends SignatureBase {
  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeaders: Map<number, unknown>,
    public readonly signature: Uint8Array,
  ) {
    super(protectedHeaders, unprotectedHeaders, signature);
  }

  private static Signature(
    bodyProtectedHeaders: Uint8Array | undefined,
    protectedHeaders: Uint8Array | undefined,
    applicationHeaders: Uint8Array | undefined,
    payload: Uint8Array
  ) {
    return encoder.encode([
      'Signature',
      bodyProtectedHeaders || new Uint8Array(),
      protectedHeaders || new Uint8Array(),
      applicationHeaders || new Uint8Array(),
      payload,
    ])
  }

  async verify(
    key: KeyLike | Uint8Array | COSEVerifyGetKey,
    bodyProtectedHeaders: Uint8Array | undefined,
    payload: Uint8Array,
    options?: VerifyOptions,
  ): Promise<void> {
    const toBeSigned = Signature.Signature(
      bodyProtectedHeaders,
      this.encodedProtectedHeaders,
      new Uint8Array(),
      payload
    );

    await this.internalVerify(toBeSigned, key, options);
  }

  static async sign(
    bodyProtectedHeaders: Uint8Array | undefined,
    protectedHeaders: ProtectedHeaders | ConstructorParameters<typeof ProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {
    const wProtectedHeaders = ProtectedHeaders.from(protectedHeaders);
    const alg = AlgorithmNames.get(wProtectedHeaders.get(Headers.Algorithm) as Algorithms);

    const encodedProtectedHeaders = wProtectedHeaders.encode();
    const unprotectedHeadersMapped = UnprotectedHeaders.from(unprotectedHeaders).esMap;

    const toBeSigned = Signature.Signature(
      bodyProtectedHeaders,
      encodedProtectedHeaders,
      new Uint8Array(),
      payload,
    );

    if (!alg) {
      throw new Error('The alg header must be set.');
    }

    const signature = await sign(alg, key, toBeSigned);

    return new Signature(
      encodedProtectedHeaders,
      unprotectedHeadersMapped,
      signature
    );
  }

}

addExtension({
  Class: Sign,
  tag: Sign.tag,
  encode(instance: Sign, encode: (obj: unknown) => Uint8Array) {
    return encode(instance.getContentForEncoding());
  },
  decode: (data: [Uint8Array, Map<number, unknown>, Uint8Array, ConstructorParameters<typeof Signature>[]]) => {
    const signatures = data[3].map(signature => new Signature(signature[0], signature[1], signature[2]));
    return new Sign(data[0], data[1], data[2], signatures);
  }
});
