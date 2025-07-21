import { JWKKeyType, KeyType } from "./kty.js";
import { encoder } from '../cbor.js';
import { Curve } from "./curve.js";
import { TypedMap } from "@jfromaniello/typedmap";
import { Algorithms } from "../headers.js";
import { GenerateKeyPairOptions, JWK, generateKeyPair, importJWK, exportJWK } from "jose";
import { COSEKeyParam, KTYSpecificJWKParamsRev, JWKParam, KTYSpecificJWKParams } from "./params.js";
import { JWKKeyOps, JWKKeyOpsToCOSE, KeyOps } from './key_ops.js';
import { decodeBase64URL, encodeBase64URL } from "#runtime/base64.js";
import { toBuffer } from "#runtime/buffer.js";

const toArray = (v: unknown | unknown[]) => Array.isArray(v) ? v : [v];

// @ts-ignore
export const JWKFromCOSEValue = new Map<string, (v: unknown) => string>([
  ['kty', (value: KeyType) => JWKKeyType[value]],
  ['crv', (value: Curve) => Curve[value]],
  ['alg', (value: Algorithms) => Algorithms[value]],
  ['kid', (v: Uint8Array | string) => {
    // Handle both string (backward compatibility) and Uint8Array (IANA spec)
    if (typeof v === 'string') {
      return v;
    }
    return new TextDecoder().decode(v);
  }],
  ['key_ops', (v) => toArray(v).map((value) => JWKKeyOps.get(value))],
  ...([
    'x',
    'y',
    'd',
    'k',
  ].map((param) => [param, (v: Uint8Array) => encodeBase64URL(v)]))
]);

// @ts-ignore
export const JWKToCOSEValue = new Map<string, (v: unknown) => KeyType | Uint8Array | Algorithms | KeyOps[]>([
  ['kty', (value: JWKKeyType) => JWKKeyType[value]],
  ['crv', (value: Curve) => Curve[value]],
  ['alg', (value: Algorithms) => Algorithms[value]],
  ['kid', (v: string) => toBuffer(v)],
  ['key_ops', (v) => toArray(v).map((value) => JWKKeyOpsToCOSE.get(value)).flat()],
  ...([
    'x',
    'y',
    'd',
    'k',
  ].map((label) => [label, (v: Uint8Array) => decodeBase64URL(v)]))
]);

export class COSEKey extends TypedMap<
  [COSEKeyParam.KeyType, KeyType] |
  [COSEKeyParam.KeyID, Uint8Array] |
  [COSEKeyParam.Algorithm, Algorithms] |
  [COSEKeyParam.KeyOps, KeyOps[]] |
  [COSEKeyParam.BaseIV, Uint8Array] |
  [COSEKeyParam.Curve, Curve] |
  [COSEKeyParam.x, Uint8Array] |
  [COSEKeyParam.y, Uint8Array] |
  [COSEKeyParam.d, Uint8Array] |
  [COSEKeyParam.k, Uint8Array]
> {
  /**
   * Import a COSEKey either decoded as Map<number, unknown> or as an encoded CBOR.
   *
   * @param data {Uint8Array | Map<number, unknown>}
   * @returns
   */
  static import(data: Uint8Array | Map<number, unknown>): COSEKey {
    if (data instanceof Uint8Array) {
      const decoded = encoder.decode(data);
      return new COSEKey(decoded);
    } else {
      return new COSEKey(data as ConstructorParameters<typeof COSEKey>[0]);
    }
  }

  /**
   *
   * Create a COSEKey from a JWK.
   *
   * @param jwk {JWK} - A JWK.
   * @returns
   */
  static fromJWK(jwk: JWK): COSEKey {
    const coseKey = new COSEKey();
    const kty = jwk.kty;
    for (const [key, value] of Object.entries(jwk)) {
      const jwkKey = KTYSpecificJWKParamsRev[kty!]?.get(key) ||
        JWKParam[key as keyof typeof JWKParam] as number;
      const formatter = JWKToCOSEValue.get(key);
      if (jwkKey && formatter) {
        coseKey.set(jwkKey, formatter(value));
      }
    }
    return coseKey;
  }

  /**
   *
   * Generate a random COSEKey for the provided alg.
   *
   * @param alg {Algorithms} - The algorithm to use.
   * @param [options] {Omit<GenerateKeyPairOptions, 'extractable'>} - The options to use.
   * @param [options.crv] {Curve} - The curve to use for EC keys.
   * @param [options.modulusLength] {number} - The modulus length to use for RSA keys.
   * @returns
   */
  static async generate(
    alg: Algorithms,
    options: Omit<GenerateKeyPairOptions, 'extractable'> = {}
  ): Promise<{ privateKey: COSEKey, publicKey: COSEKey }> {
    const { privateKey, publicKey } = await generateKeyPair(
      Algorithms[alg], {
      ...options ?? {},
      extractable: true
    });
    return {
      privateKey: COSEKey.fromJWK(await exportJWK(privateKey)),
      publicKey: COSEKey.fromJWK(await exportJWK(publicKey)),
    };
  }

  /**
   *
   * Returns a JWK representation of the COSEKey.
   *
   * @returns {JWK} - The JWK representation of the COSEKey.
   */
  toJWK(): JWK {
    const result: JWK = {};
    const kty = JWKKeyType[this.get(COSEKeyParam.KeyType) as number];
    for (const [key, value] of this) {
      const jwkKey = KTYSpecificJWKParams[kty]?.get(key) ?? JWKParam[key];
      const parser = JWKFromCOSEValue.get(jwkKey);
      if (parser && jwkKey) {
        const parsed = parser(value);
        result[jwkKey] = parsed;
      }
    }
    return result;
  }

  /**
   * Create a KeyLike from the COSEKey.
   *
   * KeyLike are runtime-specific classes representing asymmetric keys or symmetric secrets.
   * These are instances of CryptoKey and additionally KeyObject in Node.js runtime.
   * Uint8Array instances are also accepted as symmetric secret representation only.
   *
   * @returns {ReturnType<typeof importJWK> } - The KeyLike representation of the COSEKey.
   */
  toKeyLike(): ReturnType<typeof importJWK> {
    return importJWK(this.toJWK());
  }

  /**
   *
   * Encode the COSEKey as a CBOR buffer.
   *
   * @returns {Uint8Array} - The encoded COSEKey.
   */
  encode(): Uint8Array {
    return encoder.encode(this.esMap);
  }
}
