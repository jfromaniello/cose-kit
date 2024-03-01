import { KeyLike } from 'jose';
import { COSEVerifyGetKey } from '../jwks/local.js';
import { AlgorithmNames, Algorithms, Headers, ProtectedHeaders, UnprotectedHeaders } from '../headers.js';
import sign from '#runtime/sign.js';
import { SignatureBase, VerifyOptions } from './SignatureBase.js';
import { encoder, addExtension } from '../cbor.js';
import { decode } from "./decode.js";

/**
 * Decoded COSE_Sign1 structure.
 */
export class Sign1 extends SignatureBase {
  constructor(
    protectedHeaders: Map<number, unknown> | Uint8Array,
    unprotectedHeaders: Map<number, unknown>,
    public readonly payload: Uint8Array,
    signature: Uint8Array,
  ) {
    super(protectedHeaders, unprotectedHeaders, signature);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.signature,
    ];
  }

  private static Signature1(
    protectedHeaders: Uint8Array,
    applicationHeaders: Uint8Array,
    payload: Uint8Array,
  ) {
    return encoder.encode([
      'Signature1',
      protectedHeaders,
      applicationHeaders,
      payload,
    ]);
  }

  /**
   *
   * Verifies the signature of this instance using the given key.
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
    const toBeSigned = Sign1.Signature1(
      this.encodedProtectedHeaders || new Uint8Array(),
      options?.externalAAD ?? new Uint8Array(),
      options?.detachedPayload ?? this.payload,
    );
    await this.internalVerify(toBeSigned, key, options);
  }

  public async verifyX509(
    roots: string[]
  ) {
    const { publicKey } = await this.verifyX509Chain(roots);
    return this.verify(publicKey);
  }

  static async sign(
    protectedHeaders: ProtectedHeaders | ConstructorParameters<typeof ProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {

    const wProtectedHeaders = ProtectedHeaders.wrap(protectedHeaders);

    if (!wProtectedHeaders.has(Headers.Algorithm)) {
      throw new Error('The alg header must be set.');
    }

    const alg = AlgorithmNames.get(wProtectedHeaders.get(Headers.Algorithm) as Algorithms);

    const encodedProtectedHeaders = encoder.encode(wProtectedHeaders.esMap);

    const unprotectedHeadersMap = UnprotectedHeaders.wrap(unprotectedHeaders).esMap;

    const toBeSigned = Sign1.Signature1(
      encodedProtectedHeaders,
      new Uint8Array(),
      payload,
    );

    if (!alg) {
      throw new Error('The alg header must be set.');
    }

    const signature = await sign(alg, key, toBeSigned);

    return new Sign1(
      encodedProtectedHeaders,
      unprotectedHeadersMap,
      payload,
      signature
    );
  }

  /**
  *
  * Decode a COSE_Sign1 structure from a buffer.
  *
  * @param cose {Uint8Array} - The buffer containing the Cose Sign1 tagged or untagged message.
  * @returns {Sign1} - The decoded COSE_Sign1 structure.
  */
  static decode(cose: Uint8Array): Sign1 {
    return decode(cose, Sign1);
  }

  static tag = 18;
}

addExtension({
  Class: Sign1,
  tag: Sign1.tag,
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Sign1>) => {
    return new Sign1(data[0], data[1], data[2], data[3]);
  }
});

