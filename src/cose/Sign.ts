import { Encoder, } from 'cbor-x';
import { SignatureBase, WithHeaders } from './SignatureBase.js';
import { KeyLike } from 'jose';
import verify from "#runtime/verify.js";
import { COSEVerifyGetKey } from '../jwks/local.js';
import { UnprotectedHeaders, ProtectedHeader, mapUnprotectedHeaders, encodeProtectedHeaders } from '../headers.js';
import sign from '#runtime/sign.js';
import { encoder, addExtension } from '../cbor.js';

export class Sign extends WithHeaders {
  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    unprotectedHeader: Map<number, unknown>,
    public readonly payload: Uint8Array,
    public readonly signatures: Signature[]) {
    super(protectedHeader, unprotectedHeader);
  }

  public encode(extEncoder: Encoder) {
    return extEncoder.encode([
      this.encodedProtectedHeader,
      this.unprotectedHeader,
      this.payload,
      this.signatures.map((signature) => [
        signature.protectedHeader,
        signature.unprotectedHeader,
        signature.signature
      ]),
    ]);
  }

  public async verify(
    keys: KeyLike[] | Uint8Array[] | COSEVerifyGetKey,
  ): Promise<boolean> {
    const results = await Promise.all(this.signatures.map(async (signature, index) => {
      const keyToUse = Array.isArray(keys) ? keys[index] : keys;
      return signature.verify(keyToUse, this.encodedProtectedHeader, this.payload);
    }));

    return results.every(Boolean);
  }

  public async verifyX509(
    roots: string[]
  ): Promise<boolean> {
    const results = await Promise.all(this.signatures.map(async (signature) => {
      const key = await signature.verifyX509Chain(roots);
      return signature.verify(key, this.encodedProtectedHeader, this.payload);
    }));

    return results.every(Boolean);
  }

  static async sign(
    bodyProtectedHeader: ProtectedHeader,
    unprotectedHeader: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    signers: {
      key: KeyLike | Uint8Array,
      protectedHeader: ProtectedHeader,
      unprotectedHeader?: UnprotectedHeaders,
    }[],
  ): Promise<Sign> {
    const encodedProtectedHeaders = encodeProtectedHeaders(bodyProtectedHeader);
    const unprotectedHeadersMap = mapUnprotectedHeaders(unprotectedHeader);
    const signatures = await Promise.all(signers.map(async ({ key, protectedHeader, unprotectedHeader }) => {
      return Signature.sign(
        encodedProtectedHeaders,
        protectedHeader,
        unprotectedHeader,
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
}

export class Signature extends SignatureBase {

  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeader: Map<number, unknown>,
    public readonly signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, signature);
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
    payload: Uint8Array
  ): Promise<boolean> {
    if (typeof key === 'function') {
      key = await key(this);
    }

    if (!key) {
      throw new Error('key not found');
    }

    const toBeSigned = Signature.Signature(
      bodyProtectedHeaders,
      this.encodedProtectedHeader,
      new Uint8Array(),
      payload
    );

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return verify(this.algName, key, this.signature, toBeSigned);
  }

  static async sign(
    bodyProtectedHeaders: Uint8Array | undefined,
    protectedHeader: ProtectedHeader,
    unprotectedHeader: UnprotectedHeaders | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {
    const { alg } = protectedHeader;
    const encodedProtectedHeaders = encodeProtectedHeaders(protectedHeader);
    const unprotectedHeadersMapped = mapUnprotectedHeaders(unprotectedHeader);

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

addExtension(extEncoder => ({
  Class: Sign,
  tag: 98,
  encode(instance: Sign) {
    return instance.encode(extEncoder);
  },
  decode: (data: [Uint8Array, Map<number, unknown>, Uint8Array, ConstructorParameters<typeof Sign>[]]) => {
    const signatures = data[3].map(signature => new Signature(signature[0], signature[1], signature[2]));
    return new Sign(data[0], data[1], data[2], signatures);
  }
}))
