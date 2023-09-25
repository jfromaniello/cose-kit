import { ValueToKeyType } from "./kty.js";
import { Label, ValueToLabel } from './labels.js';
import { encoder } from '../cbor.js';
import { JWK, importJWK, KeyLike } from 'jose';
import { ValuesToCurves } from "./algs.js";
import { encodeBase64URL } from '#runtime/base64.js'

// @ts-ignore
const parameterParsers = new Map<number, (v: unknown) => unknown>([
  [Label.kty, (value: number) => ValueToKeyType.get(value)],
  [Label.crv, (value: number) => ValuesToCurves.get(value)],
  [Label.kid, v => v],
  [Label.x, encodeBase64URL],
  [Label.y, encodeBase64URL],
  [Label.d, encodeBase64URL],
]);

export function COSEKeyToJWK(coseKey: Uint8Array): JWK {
  const decoded = encoder.decode(coseKey) as Map<number, any>;
  const result: JWK = {};
  for (const [key, value] of decoded) {
    const jwkKey = ValueToLabel.get(key);
    const parser = parameterParsers.get(key);
    if (parser && jwkKey) {
      result[jwkKey] = parser(value);
    }
  }
  return result;
}

export async function importCOSEKey(coseKey: Uint8Array): Promise<Uint8Array | KeyLike> {
  const jwk = COSEKeyToJWK(coseKey);
  return importJWK(jwk);
}
