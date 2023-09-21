import { Encoder } from 'cbor-x';
import { KeyLike, importX509 } from 'jose';
import { pkijs } from '#runtime/pkijs';
import { decodeBase64 } from '#runtime/base64';
import { X509InvalidCertificateChain, X509NoMatchingCertificate } from '../util/errors';
import { certToPEM, pemToCert } from '../util/cert';
import { headers, algs } from '../constants';

const encoder = new Encoder({
  tagUint8Array: false,
  useRecords: false,
  mapsAsObjects: false,
  // eslint-disable-next-line @typescript-eslint/ban-ts-comment
  // @ts-ignore
  useTag259ForMaps: false,
});

export class WithHeaders {
  #decodedProtectedHeader?: Map<number, unknown>;

  protected encodedProtectedHeader?: Uint8Array;

  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    public readonly unprotectedHeader: Map<number, unknown>) {
    if (protectedHeader instanceof Uint8Array) {
      this.encodedProtectedHeader = protectedHeader;
    } else {
      this.#decodedProtectedHeader = protectedHeader;
      // TODO: https://github.com/kriszyp/cbor-x/issues/83
      this.encodedProtectedHeader = encoder.encode(protectedHeader);
    }
  }

  public get protectedHeader(): Map<number, unknown> {
    if (!this.#decodedProtectedHeader) {
      if (!this.encodedProtectedHeader || this.encodedProtectedHeader.byteLength === 0) {
        this.#decodedProtectedHeader = new Map();
      } else {
        this.#decodedProtectedHeader = encoder.decode(this.encodedProtectedHeader as Uint8Array);
      }
    }
    return this.#decodedProtectedHeader as Map<number, unknown>;
  }
}

export class SignatureBase extends WithHeaders {
  constructor(
    protectedHeader: Uint8Array | Map<number, unknown>,
    unprotectedHeader: Map<number, unknown>,
    public readonly signature: Uint8Array,
  ) {
    super(protectedHeader, unprotectedHeader);
  }

  /**
      This parameter is used to indicate the algorithm used for the
      security processing.  This parameter MUST be authenticated where
      the ability to do so exists.  This support is provided by AEAD
      algorithms or construction (COSE_Sign, COSE_Sign0, COSE_Mac, and
      COSE_Mac0).  This authentication can be done either by placing the
      header in the protected header bucket or as part of the externally
      supplied data.  The value is taken from the "COSE Algorithms"
      registry (see Section 16.4).
   */
  public get alg(): number | undefined {
    return this.protectedHeader.get(headers.alg) as number ||
      this.unprotectedHeader.get(headers.alg) as number;
  }

  public get algName(): string | undefined {
    return this.alg ? algs.get(this.alg)?.name : undefined;
  }

  /**
      This parameter identifies one piece of data that can be used as
      input to find the needed cryptographic key.  The value of this
      parameter can be matched against the 'kid' member in a COSE_Key
      structure.  Other methods of key distribution can define an
      equivalent field to be matched.  Applications MUST NOT assume that
      'kid' values are unique.  There may be more than one key with the
      same 'kid' value, so all of the keys associated with this 'kid'
      may need to be checked.  The internal structure of 'kid' values is
      not defined and cannot be relied on by applications.  Key
      identifier values are hints about which key to use.  This is not a
      security-critical field.  For this reason, it can be placed in the
      unprotected headers bucket.
   */
  public get kid(): Uint8Array | undefined {
    return this.protectedHeader.get(headers.kid) as Uint8Array ||
      this.unprotectedHeader.get(headers.kid) as Uint8Array;
  }

  public get x5bag(): Uint8Array[] | undefined {
    const x5bag = this.protectedHeader.get(headers.x5bag) ||
      this.unprotectedHeader.get(headers.x5bag);
    if (!x5bag) { return }
    return Array.isArray(x5bag) ? x5bag : [x5bag];
  }

  public get x5chain(): Uint8Array[] | undefined {
    const x5chain = this.protectedHeader.get(headers.x5chain) ||
      this.unprotectedHeader.get(headers.x5chain);
    if (!x5chain) { return }
    return Array.isArray(x5chain) ? x5chain : [x5chain];
  }

  async verifyX509Chain(
    caRoots: string[],
  ): Promise<KeyLike> {
    if (!this.x5chain || this.x5chain.length === 0) { throw new X509NoMatchingCertificate(); }

    const chainEngine = new pkijs.CertificateChainValidationEngine({
      certs: this.x5chain.map((c) => pkijs.Certificate.fromBER(c)),
      trustedCerts: caRoots.map((c) => pkijs.Certificate.fromBER(decodeBase64(pemToCert(c)))),
    });

    const chain = await chainEngine.verify();

    if (!chain.result) {
      throw new X509InvalidCertificateChain(`Invalid certificate chain: ${chain.resultMessage}`);
    }

    const x509Cert = certToPEM(this.x5chain[0]);

    return importX509(
      x509Cert,
      this.algName as string
    );
  }
}
