// import decrypt from "#runtime/decrypt.js";
// import encrypt from "#runtime/encrypt.js";
// import { concat } from '../lib/buffer_utils.js';

// import { KeyLike } from 'jose';
import { addExtension, encoder } from '../cbor.js';
import { COSEBase } from './COSEBase.js';
import * as errors from "../util/errors.js";
import validateAlgorithms from "../lib/validate_algorithms.js";
import { Direct, EncryptProtectedHeaders, EncryptionAlgorithmNames, EncryptionAlgorithms, Headers, SupportedEncryptionAlgorithms, UnprotectedHeaders } from '../headers.js';

import { decode } from "./decode.js";
import { KeyLike } from 'jose';
import { DecryptOptions } from './Encrypt0.js';
import decrypt from '#runtime/decrypt.js';
import { COSEKeyParam } from '../key/index.js';
import { COSEKey } from "../key/COSEKey.js";
import { concat } from '../lib/buffer_utils.js';
import generateIv from '../lib/iv.js';
import encrypt from '#runtime/encrypt.js';


/**
 * Decoded COSE_Encrypt0 structure.
 */
export class Encrypt extends COSEBase {
  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    unprotectedHeaders: Map<number, unknown>,
    public readonly ciphertext: Uint8Array,
    public readonly recipients: Recipient[]) {
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
  private static createAAD(
    protectedHeaders: Uint8Array,
    externalAAD: Uint8Array,
  ) {
    return encoder.encode([
      'Encrypt',
      protectedHeaders,
      externalAAD
    ]);
  }

  public getContentForEncoding() {
    const mapRecipient = (r: Recipient) => {
      const result: unknown[] = [
        r.protectedHeaders,
        r.unprotectedHeaders,
        r.ciphertext ?? new Uint8Array(),
      ];
      if (r.recipients && Array.isArray(r.recipients)) {
        result.push(r.recipients.map(mapRecipient));
      }
      return result;
    };
    return [
      this.encodedProtectedHeaders,
      this.unprotectedHeaders,
      this.ciphertext,
      this.recipients.map(mapRecipient),
    ];
  }

  /**
   *
   * Decode a COSE_Encrypt0 structure from a buffer.
   *
   * @param cose {Uint8Array} - The buffer containing the Cose Encrypt0 tagged or untagged message.
   * @returns {Encrypt0} - The decoded COSE_Encrypt0 structure.
   */
  static decode(cose: Uint8Array): Encrypt {
    return decode(cose, Encrypt);
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
    key: COSEKey | KeyLike | Uint8Array,
    options?: DecryptOptions,
  ): Promise<Uint8Array> {

    if (this.recipients.length > 1 || this.recipients.some(r => r.unprotectedHeaders.get(Headers.Algorithm) !== -6)) {
      throw new Error('Multiple recipients or recipient with non-direct algorithm not supported');
    }

    const ciphertextWithTag = options?.detachedPayload ?? this.ciphertext;
    const aad = Encrypt.createAAD(
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

    let iv: Uint8Array;

    if (this.unprotectedHeaders.has(Headers.IV) && this.unprotectedHeaders.has(Headers.PartialIV)) {
      throw new errors.COSEInvalid('IV and Partial IV must not both be present in the COSE message.');
    } else if (this.unprotectedHeaders.has(Headers.PartialIV)) {
      if (!(key instanceof COSEKey) || !key.has(COSEKeyParam.BaseIV)) {
        throw new errors.COSEInvalid('Key must be a COSEKey instance with Base IV to use Partial IV');
      }
      iv = concat(key.get(COSEKeyParam.BaseIV) as Uint8Array, this.unprotectedHeaders.get(Headers.PartialIV) as Uint8Array);
    } else if (this.unprotectedHeaders.has(Headers.IV)) {
      iv = this.unprotectedHeaders.get(Headers.IV) as Uint8Array;
    } else {
      throw new errors.COSEInvalid('IV or Partial IV must be present in the COSE message.');
    }

    //TODO: support different tag size??
    const tag = ciphertextWithTag.slice(-16);
    const ciphertext = ciphertextWithTag.slice(0, -16);

    const decryptKey = key instanceof COSEKey ? (await key.toKeyLike()) : key;
    return decrypt(this.algName, decryptKey, ciphertext, iv, tag, aad);
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
    key: COSEKey | KeyLike | Uint8Array,
    externalAAD: Uint8Array = new Uint8Array(),
    recipients: Recipient[]
  ): Promise<Encrypt> {

    if (recipients.length > 1 || recipients.some(r => r.unprotectedHeaders.get(Headers.Algorithm) !== -6)) {
      throw new Error('Multiple recipients or recipient with non-direct algorithm not supported');
    }

    const wProtectedHeaders = EncryptProtectedHeaders.wrap(protectedHeaders);

    const alg = EncryptionAlgorithmNames.get(
      wProtectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms
    );

    if (!alg) {
      throw new Error(`The protected header [${Headers.Algorithm}] (Algorithm) must be valid.`);
    }

    //clone and wrap
    const wUnprotectedHeaders = UnprotectedHeaders.wrap([...(unprotectedHeaders || [])]);
    let iv = wUnprotectedHeaders.get(Headers.IV);

    if (!iv) {
      const partialIV = wUnprotectedHeaders.get(Headers.PartialIV);
      if (partialIV) {
        if (!(key instanceof COSEKey) || !key.has(COSEKeyParam.BaseIV)) {
          throw new errors.COSEInvalid('Key must be a COSEKey instance with Base IV to use Partial IV');
        }
        iv = concat(
          key.get(COSEKeyParam.BaseIV) as Uint8Array,
          partialIV
        );
      } else {
        iv = generateIv(alg);
        wUnprotectedHeaders.set(Headers.IV, iv);
      }
    }

    const aad = Encrypt.createAAD(
      encoder.encode(wProtectedHeaders.esMap),
      externalAAD
    );

    const encryptKey = key instanceof COSEKey ? (await key.toKeyLike()) : key;

    const { ciphertext, tag } = await encrypt(alg, content, encryptKey, iv, aad);
    const r = concat(ciphertext, tag);

    return new Encrypt(
      wProtectedHeaders.esMap,
      wUnprotectedHeaders.esMap,
      r,
      recipients
    );
  }

  static tag = 96;
}

export class Recipient extends COSEBase {
  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    unprotectedHeaders: Map<number, unknown>,
    public readonly ciphertext?: Uint8Array,
    public readonly recipients?: Recipient[]) {
    super(protectedHeaders, unprotectedHeaders);
  }

  static create(
    protectedHeaders: EncryptProtectedHeaders | ConstructorParameters<typeof EncryptProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined,
  ): Recipient {
    const wProtectedHeaders = EncryptProtectedHeaders.wrap(protectedHeaders);
    const wUnprotectedHeaders = UnprotectedHeaders.wrap(unprotectedHeaders);

    return new Recipient(
      wProtectedHeaders.esMap,
      wUnprotectedHeaders.esMap
    );
  }
  // private static createAAD(
  //   bodyProtectedHeaders: Uint8Array | undefined,
  //   protectedHeaders: Uint8Array,
  //   externalAAD: Uint8Array,
  // ) {
  //   return encoder.encode([
  //     'Enc_Recipient',
  //     bodyProtectedHeaders,
  //     protectedHeaders,
  //     externalAAD
  //   ]);
  // }


  public get alg(): EncryptionAlgorithms | Direct | undefined {
    return this.protectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms ||
      this.unprotectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms;
  }

  public get algName(): SupportedEncryptionAlgorithms | undefined {
    return this.alg && this.alg !== -6 ? EncryptionAlgorithmNames.get(this.alg) : undefined;
  }

  public hasSupportedAlg() {
    return !!this.algName;
  }

  //   /**
  //  * Decrypt and verify the instance using the given key.
  //  *
  //  * @param {KeyLike | Uint8Array} key - The key to verify the signature with.
  //  * @param {VerifyOptions} [options] - Decrypt options.
  //  * @param {EncryptionAlgorithms[]} [options.algorithms] - List of allowed algorithms
  //  * @param {Uint8Array} [options.externalAAD] - External Additional Associated Data
  //  * @param {Uint8Array} [options.detachedPayload] - The detached payload to verify the signature with.
  //  * @returns {Boolean} - The result of the signature verification.
  //  */
  //   public async decrypt(
  //     key: KeyLike | Uint8Array,
  //     parent: Encrypt,
  //     options?: DecryptOptions,
  //   ): Promise<Uint8Array> {
  //     const aad = Recipient.createAAD(
  //       parent.protectedHeaders ? encoder.encode(parent.protectedHeaders) : new Uint8Array(),
  //       this.encodedProtectedHeaders ?? new Uint8Array(),
  //       options?.externalAAD ?? new Uint8Array(),
  //     );

  //     console.log('aad:', aad.toString('hex'));

  //     let alg = this.alg;
  //     let iv: Uint8Array;
  //     let ciphertextWithTag = this.ciphertext;

  //     if (alg === -6) {
  //       alg = parent.protectedHeaders.get(Headers.Algorithm) as EncryptionAlgorithms;
  //       iv = parent.unprotectedHeaders.get(Headers.IV) as Uint8Array;
  //       ciphertextWithTag = parent.ciphertext;
  //     } else {
  //       iv = this.unprotectedHeaders.get(Headers.IV) as Uint8Array;
  //     }

  //     const algName = EncryptionAlgorithmNames.get(alg as EncryptionAlgorithms) as string;
  //     console.log(algName);
  //     if (!alg || !EncryptionAlgorithmNames.has(alg)) {
  //       throw new errors.COSEInvalid(`Unsupported encryption algorithm ${this.alg}`);
  //     }

  //     // const algorithms = options && validateAlgorithms('algorithms', options.algorithms);

  //     // if (algorithms && !algorithms.has(this.alg)) {
  //     //   throw new errors.COSEAlgNotAllowed(
  //     //     `[${Headers.Algorithm}] (algorithm) Header Parameter not allowed`
  //     //   );
  //     // }

  //     //TODO: support different tag size??
  //     const tag = ciphertextWithTag.slice(-16);
  //     const ciphertext = ciphertextWithTag.slice(0, -16);

  //     return decrypt(algName, key, ciphertext, iv, tag, aad);
  //   }
}

addExtension({
  Class: Encrypt,
  tag: Encrypt.tag,
  encode(instance: Encrypt, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: [Uint8Array, Map<number, unknown>, Uint8Array, ConstructorParameters<typeof Recipient>[]]) => {
    const recipients = data[3].map(rec => new Recipient(rec[0], rec[1], rec[2], rec[3]));
    return new Encrypt(data[0], data[1], data[2], recipients);
  }
});

