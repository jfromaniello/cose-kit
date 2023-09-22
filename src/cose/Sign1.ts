import verify from "#runtime/verify";
import { KeyLike } from 'jose';
import { COSEVerifyGetKey } from '../jwks/local';
import { ProtectedHeader, UnprotectedHeaders, algsToValue, headers } from '../headers';
import sign from '#runtime/sign';
import { fromUTF8 } from '../lib/buffer_utils';
import { SignatureBase } from './SignatureBase';
import { encoder, addExtension } from '../cbor';
import { Encoder } from "cbor-x";

export class Sign1 extends SignatureBase {
  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    public readonly payload: Uint8Array,
    signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, signature);
  }

  public encode(extEncoder: Encoder) {
    return extEncoder.encode([
      this.encodedProtectedHeader,
      this.unprotectedHeader,
      this.payload,
      this.signature,
    ]);
  }

  private static Signature1(
    protectedHeader: Uint8Array,
    applicationHeaders: Uint8Array,
    payload: Uint8Array,
  ) {
    return encoder.encode([
      'Signature1',
      protectedHeader,
      applicationHeaders,
      payload,
    ]);
  }

  public async verify(key: KeyLike | Uint8Array | COSEVerifyGetKey) {
    if (typeof key === 'function') {
      key = await key(this);
    }

    if (!key) {
      throw new Error('key not found');
    }

    const toBeSigned = Sign1.Signature1(
      this.encodedProtectedHeader || new Uint8Array(),
      new Uint8Array(),
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
    const key = await this.verifyX509Chain(roots);
    return this.verify(key);
  }

  static async sign(
    protectedHeader: ProtectedHeader,
    unprotectedHeader: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {
    const { alg } = protectedHeader;

    const encodedProtectedHeaders = encoder.encode(new Map(Object.entries(protectedHeader).map(([k, v]: [string, unknown]) => {
      if (k === 'alg') {
        v = algsToValue.get(v as string);
      } else if (typeof v === 'string') {
        v = fromUTF8(v);
      }
      return [headers[k], v];
    })));

    const unprotectedHeadersMap = new Map(Object.entries(unprotectedHeader || {}).map(([k, v]: [string, unknown]) => {
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

addExtension(extEncoder => ({
  Class: Sign1,
  tag: 18,
  encode(instance: Sign1) {
    return instance.encode(extEncoder);
  },
  decode: (data: ConstructorParameters<typeof Sign1>) => {
    return new Sign1(data[0], data[1], data[2], data[3]);
  }
}));
