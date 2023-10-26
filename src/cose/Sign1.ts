import verify from "#runtime/verify.js";
import { KeyLike } from 'jose';
import { COSEVerifyGetKey } from '../jwks/local.js';
import { ProtectedHeaders, UnprotectedHeaders, algsToValue, headers } from '../headers.js';
import sign from '#runtime/sign.js';
import { fromUTF8 } from '../lib/buffer_utils.js';
import { SignatureBase } from './SignatureBase.js';
import { encoder, addExtension } from '../cbor.js';

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

  public encode() {
    return encoder.encode(this);
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

  public async verify(
    key: KeyLike | Uint8Array | COSEVerifyGetKey,
    externalAAD: Uint8Array = new Uint8Array()
  ) {
    if (typeof key === 'function') {
      key = await key(this);
    }

    if (!key) {
      throw new Error('key not found');
    }

    const toBeSigned = Sign1.Signature1(
      this.encodedProtectedHeaders || new Uint8Array(),
      externalAAD,
      this.payload,
    );

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return verify(this.algName, key, this.signature, toBeSigned);
  }

  public async verifyX509(
    roots: string[]
  ) {
    const { publicKey } = await this.verifyX509Chain(roots);
    return this.verify(publicKey);
  }

  static async sign(
    protectedHeaders: ProtectedHeaders,
    unprotectedHeaders: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {
    const { alg } = protectedHeaders;

    const encodedProtectedHeaders = encoder.encode(new Map(Object.entries(protectedHeaders).map(([k, v]: [string, unknown]) => {
      if (k === 'alg') {
        v = algsToValue.get(v as string);
      } else if (typeof v === 'string') {
        v = fromUTF8(v);
      }
      return [headers[k], v];
    })));

    const unprotectedHeadersMap = new Map(Object.entries(unprotectedHeaders || {}).map(([k, v]: [string, unknown]) => {
      if (typeof v === 'string') {
        v = fromUTF8(v);
      }
      return [headers[k], v];
    }));

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
}

addExtension({
  Class: Sign1,
  tag: 18,
  encode(instance: Sign1, encodeFn: (obj: unknown) => Uint8Array) {
    return encodeFn(instance.getContentForEncoding());
  },
  decode: (data: ConstructorParameters<typeof Sign1>) => {
    return new Sign1(data[0], data[1], data[2], data[3]);
  }
});

