import verify from "#runtime/verify.js";
import sign from '#runtime/sign.js';
import { KeyLike } from 'jose';
import { addExtension, encoder } from '../cbor.js';
import { COSEBase } from './COSEBase.js';
import { Headers, MacProtectedHeaders, UnprotectedHeaders, SupportedMacAlg, MacAlgorithmNames, MacAlgorithms } from '../headers.js';
import { areEqual } from "../lib/buffer_utils.js";
import * as errors from "../util/errors.js";
import validateAlgorithms from "../lib/validate_algorithms.js";
import { decode } from "./decode.js";

type VerifyOptions = {
  externalAAD?: Uint8Array,
  detachedPayload?: Uint8Array,
  algorithms?: MacAlgorithms[]
}

/**
 * Decoded COSE_Mac0 structure.
 */
export class Mac0 extends COSEBase {
  constructor(
    protectedHeaders: Map<number, unknown> | Uint8Array,
    unprotectedHeaders: Map<number, unknown>,
    public readonly payload: Uint8Array,
    public tag: Uint8Array,
  ) {
    super(protectedHeaders, unprotectedHeaders);
  }

  private static createMAC0(
    protectedHeaders: Uint8Array,
    applicationHeaders: Uint8Array,
    payload: Uint8Array,
  ) {
    return encoder.encode([
      'MAC0',
      protectedHeaders,
      applicationHeaders,
      payload,
    ]);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.payload,
      this.tag,
    ];
  }

  /**
   * Verifies the signature of this instance using the given key.
   *
   * @param {KeyLike | Uint8Array} key - The key to verify the signature with.
   * @param {VerifyOptions} [options] - Verify options
   * @param {MacAlgorithms[]} [options.algorithms] - List of allowed algorithms
   * @param {Uint8Array} [options.externalAAD] - External Additional Associated Data
   * @param {Uint8Array} [options.detachedPayload] - The detached payload to verify the signature with.
   * @returns {Boolean} - The result of the signature verification.
   */
  public async verify(
    key: KeyLike | Uint8Array,
    options?: VerifyOptions,
  ): Promise<void> {
    const mac0Structure = Mac0.createMAC0(
      this.encodedProtectedHeaders || new Uint8Array(),
      options?.externalAAD ?? new Uint8Array(),
      options?.detachedPayload ?? this.payload,
    );

    if (!this.alg || !this.algName || !MacAlgorithmNames.has(this.alg)) {
      throw new errors.COSEInvalid(`Unsupported MAC algorithm ${this.alg}`);
    }

    const algorithms = options && validateAlgorithms('algorithms', options.algorithms);

    if (algorithms && !algorithms.has(this.alg)) {
      throw new errors.COSEAlgNotAllowed(
        `[${Headers.Algorithm}] (algorithm) Header Parameter not allowed`
      );
    }

    const isValid = await verify(this.algName, key, this.tag, mac0Structure);
    if (!isValid) {
      throw new errors.COSESignatureVerificationFailed(
        'MAC0 signature verification failed'
      );
    }
  }

  public get alg(): MacAlgorithms | undefined {
    return this.protectedHeaders.get(Headers.Algorithm) as MacAlgorithms ||
      this.unprotectedHeaders.get(Headers.Algorithm) as MacAlgorithms;
  }

  public get algName(): SupportedMacAlg | undefined {
    return this.alg ? MacAlgorithmNames.get(this.alg) : undefined;
  }

  public hasSupportedAlg() {
    return !!this.algName;
  }

  /**
   * compares the tag of this instance with the tag of the given instance
   */
  public areEqual(mac0: Mac0) {
    return areEqual(this.tag, mac0.tag);
  }

  static async create(
    protectedHeaders: MacProtectedHeaders | ConstructorParameters<typeof MacProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {

    const wProtectedHeaders = MacProtectedHeaders.wrap(protectedHeaders);

    const alg = MacAlgorithmNames.get(wProtectedHeaders.get(Headers.Algorithm) as MacAlgorithms);

    const encodedProtectedHeaders = encoder.encode(wProtectedHeaders.esMap);

    const wUnprotectedHeaders = UnprotectedHeaders.wrap(unprotectedHeaders);

    const toBeSigned = Mac0.createMAC0(
      encodedProtectedHeaders,
      new Uint8Array(),
      payload,
    );

    if (!alg) {
      throw new Error(`The [${Headers.Algorithm}] (Algorithm) header must be set.`);
    }

    const tag = await sign(alg, key, toBeSigned);

    return new Mac0(
      encodedProtectedHeaders,
      wUnprotectedHeaders.esMap,
      payload,
      tag
    );
  }

  /**
  *
  * Decode a COSE_Mac0 structure from a buffer.
  *
  * @param cose {Uint8Array} - The buffer containing the Cose Mac0 tagged or untagged message.
  * @returns {Mac0} - The decoded COSE_Mac0 structure.
  */
  static decode(cose: Uint8Array): Mac0 {
    return decode(cose, Mac0);
  }

  static tag = 17;
}

addExtension({
  Class: Mac0,
  tag: Mac0.tag,
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Mac0>) => {
    return new Mac0(data[0], data[1], data[2], data[3]);
  }
});

