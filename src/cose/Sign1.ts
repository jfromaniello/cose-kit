import { Encoder } from 'cbor-x';
import { SignatureBase } from './SignatureBase';

// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import joseVerify from "#runtime/verify";
import { KeyLike } from 'jose';
import { COSEVerifyGetKey } from '../jwks/local';

const encoder = new Encoder({
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useTag259ForMaps: false,
});

export class Sign1 extends SignatureBase {
  constructor(
    protectedHeader: Map<number, unknown> | Uint8Array,
    unprotectedHeader: Map<number, unknown>,
    public readonly payload: Uint8Array,
    signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, signature);
  }

  public encode() {
    return encoder.encode([
      this.encodedProtectedHeader,
      this.unprotectedHeader,
      this.payload,
      this.signature,
    ]);
  }

  public async verify(key: KeyLike | Uint8Array | COSEVerifyGetKey) {
    if (typeof key === 'function') {
      key = await key(this);
    }

    if (!key) {
      throw new Error('key not found');
    }

    const toBeSigned = encoder.encode([
      'Signature1',
      this.encodedProtectedHeader,
      new Uint8Array(),
      this.payload,
    ]);

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return joseVerify(this.algName, key, this.signature, toBeSigned);
  }

  public async verifyX509(
    roots: string[]
  ) {
    const key = await this.verifyX509Chain(roots);
    return this.verify(key);
  }
}
