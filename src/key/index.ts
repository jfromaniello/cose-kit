import { KEY_TYPE, COSE_KEY_TYPE } from "./kty.js";
import { LABEL, BufferTypes, COSE_LABEL, KEY_TYPE_LABELS, COSE_KEY_TYPE_LABELS } from './labels.js';
import { encoder } from '../cbor.js';
import { JWK, importJWK, KeyLike } from 'jose';
import { COSE_CURVE, CURVE } from "./crv.js";
import { COSE_KEY_OPS, KEY_OPS } from './key_ops.js';
import { decodeBase64URL, encodeBase64URL } from '#runtime/base64.js'
import { ALG, COSE_ALG } from "./alg.js";

const toArray = (v: unknown | unknown[]) => Array.isArray(v) ? v : [v];

// @ts-ignore
const parameterParsers = new Map<string, (v: unknown) => unknown>([
  ['kty', (value: number) => KEY_TYPE.get(value)],
  ['crv', (value: number) => CURVE.get(value)],
  ['alg', (value: number) => ALG.get(value)],
  ['crit', (value: number | number[]) => {
    const values = Array.isArray(value) ? value : [value];
    return values.map(v => LABEL.get(v));
  }],
  ['kid', (v) => v],
  ['key_ops', (v) => toArray(v).map((value) => KEY_OPS.get(value))],
  ...(BufferTypes.map((label: string) => [label, (v: Uint8Array) => encodeBase64URL(v)]))
]);

function decodedCOSEKeyToJWK(decoded: Map<number, unknown>): JWK {
  const result: JWK = {};
  const kty = KEY_TYPE.get(decoded.get(COSE_LABEL.get('kty')!) as number);
  for (const [key, value] of decoded) {
    const jwkKey = LABEL.get(key) || (kty && KEY_TYPE_LABELS[kty]?.get(key));
    const parser = jwkKey && parameterParsers.get(jwkKey);
    if (parser && jwkKey) {
      result[jwkKey] = parser(value);
    }
  }
  return result;
}

export function COSEKeyToJWK(coseKey: Uint8Array | Map<number, unknown>): JWK {
  let decoded: Map<number, unknown>;
  if (coseKey instanceof Uint8Array) {
    decoded = encoder.decode(coseKey) as Map<number, unknown>;
  } else {
    decoded = coseKey;
  }
  const result = decodedCOSEKeyToJWK(decoded);
  return result;
}

export async function importCOSEKey(
  coseKey: Uint8Array | Map<number, number | Uint8Array>
): Promise<Uint8Array | KeyLike> {
  const jwk = coseKey instanceof Uint8Array ?
    COSEKeyToJWK(coseKey) :
    decodedCOSEKeyToJWK(coseKey);
  return importJWK(jwk);
}

// @ts-ignore
const parameterFormatter = new Map<string, (v: unknown) => unknown>([
  ['kty', (value: string) => COSE_KEY_TYPE.get(value)],
  ['crv', (value: string) => COSE_CURVE.get(value)],
  ['alg', (value: string) => COSE_ALG.get(value)],
  ['crit', (value: string | string[]) => toArray(value).map(v => COSE_LABEL.get(v))],
  ['kid', (v) => v],
  ['key_ops', (v) => toArray(v).map((value) => COSE_KEY_OPS.get(value))],
  ...(BufferTypes.map((label: string) => [label, (v: Uint8Array) => decodeBase64URL(v)]))
]);

export function COSEKeyFromJWK(jwk: JWK): Uint8Array {
  const coseKey = new Map<number, unknown>();
  const { kty } = jwk;
  for (const [key, value] of Object.entries(jwk)) {
    const coseKeyLabel = COSE_LABEL.get(key) || COSE_KEY_TYPE_LABELS[kty!]?.get(key);
    const formatter = parameterFormatter.get(key);
    if (coseKeyLabel && formatter) {
      coseKey.set(coseKeyLabel, formatter(value));
    }
  }
  return encoder.encode(coseKey);
}
