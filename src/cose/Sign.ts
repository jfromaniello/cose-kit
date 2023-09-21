import { Encoder } from 'cbor-x';

import { SignatureBase, WithHeaders } from './SignatureBase';
import { KeyLike, importX509 } from 'jose';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import joseVerify from "#runtime/verify";
import { COSEVerifyGetKey } from '../jwks/local';
import { pkijs } from '#runtime/pkijs';
import { decodeBase64, encodeBase64 } from '#runtime/base64';

const pemToCert = (cert: string): string => {
  const pem = /-----BEGIN (\w*)-----([^-]*)-----END (\w*)-----/g.exec(cert.toString());
  if (pem && pem.length > 0) {
    return pem[2].replace(/[\n|\r\n]/g, '');
  }
  return '';
};

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

  public async verifyX509(
    roots: string[]
  ): Promise<boolean> {
    const results = await Promise.all(this.signatures.map(async (signature) => {
      return signature.verifyX509(roots, this.encodedProtectedHeader, this.payload);
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

    const toBeSigned = encoder.encode([
      'Signature',
      bodyProtectedHeaders || new Uint8Array(),
      this.encodedProtectedHeader,
      new Uint8Array(),
      payload,
    ]);

    if (!this.algName) {
      throw new Error('unknown algorithm: ' + this.alg);
    }

    return joseVerify(this.algName, key, this.signature, toBeSigned);
  }

  async verifyX509(
    caRoots: string[],
    bodyProtectedHeaders: Uint8Array | undefined,
    payload: Uint8Array
  ): Promise<boolean> {
    if (!this.x5chain || this.x5chain.length === 0) { return false; }

    const chainEngine = new pkijs.CertificateChainValidationEngine({
      certs: this.x5chain.map((c) => pkijs.Certificate.fromBER(c)),
      trustedCerts: caRoots.map((c) => pkijs.Certificate.fromBER(decodeBase64(pemToCert(c)))),
    });

    const chain = await chainEngine.verify();

    if (!chain.result) {
      throw new Error(`Invalid certificate chain: ${chain.resultMessage}`);
    }

    const x509Cert = `-----BEGIN CERTIFICATE-----
${encodeBase64(this.x5chain[0])}
-----END CERTIFICATE-----`;

    const key = await importX509(
      x509Cert,
      this.algName as string);

    return this.verify(key, bodyProtectedHeaders, payload);
  }
}
