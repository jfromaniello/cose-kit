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

function decodedCOSEKeyToJWK(decoded: Map<number, number | Uint8Array>): JWK {
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

export function COSEKeyToJWK(coseKey: Uint8Array): JWK {
  const decoded = encoder.decode(coseKey) as Map<number, number | Uint8Array>;
  const result = decodedCOSEKeyToJWK(decoded);
  return result;
}

// export async function exportCOSEKey(key: KeyLike): Promise<Uint8Array> {
//   const jwk = await JWK.asKey(key);
//   const coseKey: Map<number, number | Uint8Array> = new Map();
//   for (const [key, value] of Object.entries(jwk)) {
//     const label = ValueToLabel.get(key as Label);
//     const parser = parameterParsers.get(key as Label);
//     if (parser && label) {
//       coseKey.set(label, parser(value));
//     }
//   }
//   return encoder.encode(coseKey);
// }

export async function importCOSEKey(coseKey: Uint8Array): Promise<Uint8Array | KeyLike> {
  const jwk = COSEKeyToJWK(coseKey);
  return importJWK(jwk);
}

export async function importDecodedCOSEKey(decoded: Map<number, number | Uint8Array>): Promise<Uint8Array | KeyLike> {
  const jwk = decodedCOSEKeyToJWK(decoded);
  return importJWK(jwk);
}
