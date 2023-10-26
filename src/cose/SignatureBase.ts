import { KeyLike, importX509 } from 'jose';
import { pkijs } from '#runtime/pkijs.js';
import { decodeBase64 } from '#runtime/base64.js';
import { X509InvalidCertificateChain, X509NoMatchingCertificate } from '../util/errors.js';
import { certToPEM, pemToCert } from '../util/cert.js';
import { headers, algs } from '../headers.js';
import { WithHeaders } from './WithHeaders.js';

export class SignatureBase extends WithHeaders {
  constructor(
    protectedHeaders: Uint8Array | Map<number, unknown>,
    unprotectedHeaders: Map<number, unknown>,
    public readonly signature: Uint8Array,
  ) {
    super(protectedHeaders, unprotectedHeaders);
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
    return this.protectedHeaders.get(headers.alg) as number ||
      this.unprotectedHeaders.get(headers.alg) as number;
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
    return this.protectedHeaders.get(headers.kid) as Uint8Array ||
      this.unprotectedHeaders.get(headers.kid) as Uint8Array;
  }

  public get x5bag(): Uint8Array[] | undefined {
    const x5bag = this.protectedHeaders.get(headers.x5bag) ||
      this.unprotectedHeaders.get(headers.x5bag);
    if (!x5bag) { return }
    return Array.isArray(x5bag) ? x5bag : [x5bag];
  }

  public get x5chain(): Uint8Array[] | undefined {
    const x5chain = this.protectedHeaders.get(headers.x5chain) ||
      this.unprotectedHeaders.get(headers.x5chain);
    if (!x5chain) { return }
    return Array.isArray(x5chain) ? x5chain : [x5chain];
  }

  /**
   * Verify the x5chain content of a message with a given list of certificate authorities.
   * Returns the publicKey for message validation and
   * the raw x5chain certificate for further processing.
   *
   * @param caRoots the list of certificate authorities in pem format
   * @returns {Promise<{ publicKey: KeyLike, raw: Uint8Array }>
   */
  async verifyX509Chain(
    caRoots: string[],
  ): Promise<{ publicKey: KeyLike, raw: Uint8Array }> {
    const { x5chain } = this;

    if (!x5chain || x5chain.length === 0) { throw new X509NoMatchingCertificate(); }

    const chainEngine = new pkijs.CertificateChainValidationEngine({
      certs: x5chain.map((c) => pkijs.Certificate.fromBER(c)),
      trustedCerts: caRoots.map((c) => pkijs.Certificate.fromBER(decodeBase64(pemToCert(c)))),
    });

    const chain = await chainEngine.verify();

    if (!chain.result) {
      throw new X509InvalidCertificateChain(chain.resultMessage);
    }

    const x509Cert = certToPEM(x5chain[0]);

    const publicKey = await importX509(
      x509Cert,
      this.algName as string
    );

    return { publicKey, raw: x5chain[0] };
  }
}
