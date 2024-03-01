import decrypt from "#runtime/decrypt.js";
import encrypt from "#runtime/encrypt.js";
import { concat } from '../lib/buffer_utils.js';

import { KeyLike } from 'jose';
import { addExtension, encoder } from '../cbor.js';
import { COSEBase } from './COSEBase.js';
import * as errors from "../util/errors.js";
import validateAlgorithms from "../lib/validate_algorithms.js";
import generateIv from '../lib/iv.js';
import {
  Headers,
  EncryptionAlgorithmNames,
  EncryptionAlgorithms,
  SupportedEncryptionAlgorithms,
  EncryptProtectedHeaders,
  UnprotectedHeaders
} from '../headers.js';

import { decode } from "./decode.js";

export type DecryptOptions = {
  externalAAD?: Uint8Array,
  detachedPayload?: Uint8Array,
  algorithms?: EncryptionAlgorithms[]
}

/**
 * Decoded COSE_Encrypt0 structure.
 */
export class Encrypt0 extends COSEBase {
  constructor(
    protectedHeaders: Map<number, unknown> | Uint8Array,
    unprotectedHeaders: Map<number, unknown>,
    public readonly ciphertext: Uint8Array,
  ) {
    super(protectedHeaders, unprotectedHeaders);
  }

  /**
   * Create the COSE_Encrypt0 structure for Aditional authenticated data.
   *
   * @param protectedHeaders
   * @param applicationHeaders
   * @param ciphertext
   * @returns
   */
  private static createEncrypt0AAD(
    protectedHeaders: Uint8Array,
    externalAAD: Uint8Array,
  ) {
    return encoder.encode([
      'Encrypt0',
      protectedHeaders,
      externalAAD
    ]);
  }

  public getContentForEncoding() {
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.ciphertext,
    ];
  }

  /**
   *
   * Decode a COSE_Encrypt0 structure from a buffer.
   *
   * @param cose {Uint8Array} - The buffer containing the Cose Encrypt0 tagged or untagged message.
   * @returns {Encrypt0} - The decoded COSE_Encrypt0 structure.
   */
  static decode(cose: Uint8Array): Encrypt0 {
    return decode(cose, Encrypt0);
  }

  /**
   * Decrypt and verify the instance using the given key.
   *
   * @param {KeyLike | Uint8Array} key - The key to verify the signature with.
   * @param {VerifyOptions} [options] - Decrypt options.
   * @param {EncryptionAlgorithms[]} [options.algorithms] - List of allowed algorithms
   * @param {Uint8Array} [options.externalAAD] - External Additional Associated Data
   * @param {Uint8Array} [options.detachedPayload] - The detached payload to verify the signature with.
   * @returns {Boolean} - The result of the signature verification.
   */
  public async decrypt(
    key: KeyLike | Uint8Array,
    options?: DecryptOptions,
  ): Promise<Uint8Array> {
    const ciphertextWithTag = options?.detachedPayload ?? this.ciphertext;
    const aad = Encrypt0.createEncrypt0AAD(
      this.encodedProtectedHeaders ?? new Uint8Array(),
      options?.externalAAD ?? new Uint8Array(),
    );

    if (!this.alg || !this.algName || !EncryptionAlgorithmNames.has(this.alg)) {
      throw new errors.COSEInvalid(`Unsupported encryption algorithm ${this.alg}`);
    }

    const algorithms = options && validateAlgorithms('algorithms', options.algorithms);

    if (algorithms && !algorithms.has(this.alg)) {
      throw new errors.COSEAlgNotAllowed(
        `[${Headers.Algorithm}] (algorithm) Header Parameter not allowed`
      );
    }

    const iv = this.unprotectedHeaders.get(Headers.IV) as Uint8Array | undefined;

    //TODO: support different tag size??
    const tag = ciphertextWithTag.slice(-16);
    const ciphertext = ciphertextWithTag.slice(0, -16);

    return decrypt(this.algName, key, ciphertext, iv, tag, aad);
  }

  public get alg(): EncryptionAlgorithms | undefined {
    return this.protectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms ||
      this.unprotectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms;
  }

  public get algName(): SupportedEncryptionAlgorithms | undefined {
    return this.alg ? EncryptionAlgorithmNames.get(this.alg) : undefined;
  }

  public hasSupportedAlg() {
    return !!this.algName;
  }

  /**
   *
   * Create and encrypt a COSE_Encrypt0 message.
   *
   * @param protectedHeaders {EncryptProtectedHeaders | ConstructorParameters<typeof EncryptProtectedHeaders>[0]} - The protected headers
   * @param unprotectedHeaders {UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined} - The unprotected headers
   * @param content {Uint8Array} - The content to encrypt
   * @param key {KeyLike | Uint8Array} - The key to use to encrypt the content
   * @param [externalAAD] {Uint8Array} - External Additional Associated Data
   * @returns {Promise<Encrypt0>}
   */
  static async encrypt(
    protectedHeaders: EncryptProtectedHeaders | ConstructorParameters<typeof EncryptProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined,
    content: Uint8Array,
    key: KeyLike | Uint8Array,
    externalAAD: Uint8Array = new Uint8Array()
  ): Promise<Encrypt0> {

    const wProtectedHeaders = EncryptProtectedHeaders.wrap(protectedHeaders);

    const alg = EncryptionAlgorithmNames.get(
      wProtectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms
    );

    if (!alg) {
      throw new Error(`The protected header [${Headers.Algorithm}] (Algorithm) must be valid.`);
    }

    //clone and wrap
    const wUnprotectedHeaders = UnprotectedHeaders.wrap([...(unprotectedHeaders || [])]);
    let iv = wUnprotectedHeaders.get(Headers.IV) as Uint8Array | undefined;

    if (!iv) {
      iv = generateIv(alg);
      wUnprotectedHeaders.set(Headers.IV, iv);
    }

    const aad = Encrypt0.createEncrypt0AAD(
      encoder.encode(wProtectedHeaders.esMap),
      externalAAD
    );


    const { ciphertext, tag } = await encrypt(alg, content, key, iv, aad);
    const r = concat(ciphertext, tag);

    return new Encrypt0(
      wProtectedHeaders.esMap,
      wUnprotectedHeaders.esMap,
      r
    );
  }

  static tag = 16;
}

addExtension({
  Class: Encrypt0,
  tag: Encrypt0.tag,
  encode(instance: Encrypt0, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Encrypt0>) => {
    return new Encrypt0(...data);
  }
});

