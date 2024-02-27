import verify from "#runtime/verify.js";
import { KeyLike } from 'jose';
import { COSEVerifyGetKey } from '../jwks/local.js';
import { AlgorithmNames, Headers, ProtectedHeaders, UnprotectedHeaders } from '../headers.js';
import sign from '#runtime/sign.js';
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
    protectedHeaders: ProtectedHeaders | ConstructorParameters<typeof ProtectedHeaders>[0],
    unprotectedHeaders: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0] | undefined,
    payload: Uint8Array,
    key: KeyLike | Uint8Array,
  ) {

    const wProtectedHeaders = ProtectedHeaders.wrap(protectedHeaders);

    const alg = AlgorithmNames.get(wProtectedHeaders.get(Headers.Algorithm));

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

