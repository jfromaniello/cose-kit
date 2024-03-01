import { TypedMap } from "@jfromaniello/typedmap";
import { encoder } from "./cbor.js";
/**
 * COSE Header labels registered in the IANA "COSE Header Parameters" registry.
 * Reference: https://www.iana.org/assignments/cose/cose.xhtml#header-parameters
 */
export enum Headers {
  Algorithm = 1,
  Critical = 2,
  ContentType = 3,
  KeyID = 4,
  IV = 5,
  PartialIV = 6,
  CounterSignature = 7,
  CounterSignature0 = 9,
  CounterSignatureV2 = 11,
  CounterSignature0V2 = 12,
  X5Bag = 32,
  X5Chain = 33,
  X5T = 34,
  X5U = 35,
}

export enum Algorithms {
  EdDSA = -8,
  ES256 = -7,
  ES384 = -35,
  ES512 = -36,
  PS256 = -37,
  PS384 = -38,
  PS512 = -39,
  RS256 = -257,
  RS384 = -258,
  RS512 = -259,
}

export enum MacAlgorithms {
  HS256 = 5,
  HS384 = 6,
  HS512 = 7,
}

export enum EncryptionAlgorithms {
  A128GCM = 1,
  A192GCM = 2,
  A256GCM = 3,
  Direct = -6,
}

export type Direct = -6;

export type SupportedEncryptionAlgorithms = 'A128GCM' | 'A192GCM' | 'A256GCM';

export const EncryptionAlgorithmNames = new Map<EncryptionAlgorithms, SupportedEncryptionAlgorithms>([
  [EncryptionAlgorithms.A128GCM, 'A128GCM'],
  [EncryptionAlgorithms.A192GCM, 'A192GCM'],
  [EncryptionAlgorithms.A256GCM, 'A256GCM']
]);

export const MacAlgorithmNames = new Map<MacAlgorithms, SupportedMacAlg>([
  [MacAlgorithms.HS256, 'HS256'],
  [MacAlgorithms.HS384, 'HS384'],
  [MacAlgorithms.HS512, 'HS512']
]);

export const AlgorithmNames = new Map<Algorithms, SupportedAlgs>([
  [Algorithms.EdDSA, 'EdDSA'],
  [Algorithms.ES256, 'ES256'],
  [Algorithms.ES384, 'ES384'],
  [Algorithms.ES512, 'ES512'],
  [Algorithms.PS256, 'PS256'],
  [Algorithms.PS384, 'PS384'],
  [Algorithms.PS512, 'PS512'],
  [Algorithms.RS256, 'RS256'],
  [Algorithms.RS384, 'RS384'],
  [Algorithms.RS512, 'RS512']
]);

export type SupportedAlgs = 'EdDSA' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'RS256' | 'RS384' | 'RS512';

export class ProtectedHeaders extends TypedMap<
  [Headers.Algorithm, Algorithms] |
  [Headers.Critical, Headers[]] |
  [Headers.ContentType, number | Uint8Array] |
  [Headers.KeyID, Uint8Array] |
  [
    Omit<Headers, Headers.Algorithm | Headers.Critical | Headers.ContentType | Headers.KeyID>,
    Uint8Array | Uint8Array[] | number | number[]
  ]
> {
  /**
   * Ensure input is a ProtectedHeaders instance.
   *
   * @param headers - The headers to wrap.
   * @returns
   */
  static from(headers: ProtectedHeaders | ConstructorParameters<typeof ProtectedHeaders>[0]) {
    //similar to base class wrap
    if (headers instanceof ProtectedHeaders) {
      return headers;
    }
    return new ProtectedHeaders(headers);
  }

  /**
   * CBOR encode the hedaers instance
   * @returns {Uint8Array} - The encoded protected headers.
   */
  encode(): Uint8Array {
    return encoder.encode(this.esMap);
  }
}

export type SupportedMacAlg = 'HS256' | 'HS384' | 'HS512';

export class EncryptProtectedHeaders extends TypedMap<
  [Headers.Algorithm, EncryptionAlgorithms] |
  [Headers.Critical, Headers[]] |
  [Headers.ContentType, number | Uint8Array] |
  [Headers.KeyID, Uint8Array] |
  [
    Omit<Headers, Headers.Algorithm | Headers.Critical | Headers.ContentType | Headers.KeyID>,
    Uint8Array | number | number[]
  ]
> {
  /**
   * Ensure input is a EncryptProtectedHeaders instance.
   *
   * @param headers - The headers to wrap.
   * @returns
   */
  static from(headers: EncryptProtectedHeaders | ConstructorParameters<typeof EncryptProtectedHeaders>[0]) {
    //similar to base class wrap
    if (headers instanceof EncryptProtectedHeaders) {
      return headers;
    }
    return new MacProtectedHeaders(headers);
  }
}

export class MacProtectedHeaders extends TypedMap<
  [Headers.Algorithm, MacAlgorithms] |
  [Headers.Critical, Headers[]] |
  [Headers.ContentType, number | Uint8Array] |
  [Headers.KeyID, Uint8Array] |
  [
    Omit<Headers, Headers.Algorithm | Headers.Critical | Headers.ContentType | Headers.KeyID>,
    Uint8Array | number | number[]
  ]
> {
  /**
   * Ensure input is a MacProtectedHeaders instance.
   *
   * @param headers - The headers to wrap.
   * @returns
   */
  static from(headers: MacProtectedHeaders | ConstructorParameters<typeof MacProtectedHeaders>[0]) {
    //similar to base class wrap
    if (headers instanceof MacProtectedHeaders) {
      return headers;
    }
    return new MacProtectedHeaders(headers);
  }
}

export class UnprotectedHeaders extends TypedMap<
  [Headers.ContentType, number | Uint8Array] |
  [Headers.KeyID, Uint8Array] |
  [Headers.IV, Uint8Array] |
  [Headers.PartialIV, Uint8Array] |
  [Headers.X5Chain, Uint8Array | Uint8Array[]] |
  [
    Exclude<Headers, Headers.ContentType | Headers.KeyID | Headers.PartialIV | Headers.X5Chain>,
    number | number[] | Uint8Array | Uint8Array[]
  ]
> {
  /**
 * Ensure input is a MacProtectedHeaders instance.
 *
 * @param headers - The headers to wrap.
 * @returns
 */
  static from(headers: UnprotectedHeaders | ConstructorParameters<typeof UnprotectedHeaders>[0]) {
    //similar to base class wrap
    if (headers instanceof UnprotectedHeaders) {
      return headers;
    }
    return new UnprotectedHeaders(headers);
  }
}
