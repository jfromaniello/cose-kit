import verify from "#runtime/verify.js";
import sign from '#runtime/sign.js';
import { KeyLike } from 'jose';
import { addExtension, encoder } from '../cbor.js';
import { WithHeaders } from './WithHeaders.js';
import { Headers, MacProtectedHeaders, UnprotectedHeaders, SupportedMacAlg, MacAlgorithmNames, MacAlgorithms } from '../headers.js';
import { areEqual } from "../lib/buffer_utils.js";

export class Mac0 extends WithHeaders {
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

  public encode() {
    return encoder.encode(this);
  }

  /**
   * Verifies the signature of this instance using the given key.
   *
   * @param {KeyLike | Uint8Array} key - The key to verify the signature with.
   * @param {Uint8Array} externalAAD - External Additional Associated Data
   * @param {Uint8Array} detachedPayload - The detached payload to verify the signature with.
   * @returns {Boolean} - The result of the signature verification.
   */
  public async verify(
    key: KeyLike | Uint8Array,
    externalAAD: Uint8Array = new Uint8Array(),
    detachedPayload?: Uint8Array
  ): Promise<boolean> {
    if (!key) {
      throw new Error('key not found');
    }

    const mac0Structure = Mac0.createMAC0(
      this.encodedProtectedHeaders || new Uint8Array(),
      externalAAD,
      detachedPayload ?? this.payload,
    );

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return verify(this.algName, key, this.tag, mac0Structure);
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

    const alg = MacAlgorithmNames.get(wProtectedHeaders.get(Headers.Algorithm));

    const encodedProtectedHeaders = encoder.encode(wProtectedHeaders.esMap);

    const wUnprotectedHeaders = UnprotectedHeaders.wrap(unprotectedHeaders);

    const toBeSigned = Mac0.createMAC0(
      encodedProtectedHeaders,
      new Uint8Array(),
      payload,
    );

    if (!alg) {
      throw new Error('The alg header must be set.');
    }

    const tag = await sign(alg, key, toBeSigned);

    return new Mac0(
      encodedProtectedHeaders,
      wUnprotectedHeaders.esMap,
      payload,
      tag
    );
  }
}

addExtension({
  Class: Mac0,
  tag: 17,
  encode(instance: Mac0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Mac0>) => {
    return new Mac0(data[0], data[1], data[2], data[3]);
  }
});

