import { Encoder } from 'cbor-x';
import { SignatureBase, WithHeaders } from './SignatureBase';
import { KeyLike } from 'jose';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import joseVerify from "jose/verify";
import { COSEVerifyGetKey } from '../jwks/local';

const encoder = new Encoder({
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useTag259ForMaps: false,
});

export class Sign extends WithHeaders {
  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    unprotectedHeader: Map<number, unknown>,
    public readonly payload: Uint8Array,
    public readonly signatures: Signature[]) {
    super(protectedHeader, unprotectedHeader);
  }


  public encode() {
    return encoder.encode([
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
}

export class Signature extends SignatureBase {
  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeader: Map<number, unknown>,
    public readonly signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader, signature);
  }

  public async verify(
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

    const toBeSigned = encoder.encode([
      'Signature',
      bodyProtectedHeaders || Buffer.alloc(0),
      this.encodedProtectedHeader,
      Buffer.alloc(0),
      payload,
    ]);

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return joseVerify(this.algName, key, this.signature, toBeSigned);
  }
}
