import { fromUTF8 } from "./lib/buffer_utils.js";
import { encoder } from "./cbor.js";

export const algs = new Map<number, { name: string, hash?: string }>(
  [
    [-8, { name: 'EdDSA' }],
    [-7, { name: 'ES256', hash: 'SHA-256' }],
    [-35, { name: 'ES384', hash: 'SHA-384' }],
    [-36, { name: 'ES512', hash: 'SHA-512' }],
    [-37, { name: 'PS256', hash: 'SHA-256' }],
    [-38, { name: 'PS384', hash: 'SHA-384' }],
    [-39, { name: 'PS512', hash: 'SHA-512' }],
    [-257, { name: 'RS256', hash: 'SHA-256' }],
    [-258, { name: 'RS384', hash: 'SHA-384' }],
    [-259, { name: 'RS512', hash: 'SHA-512' }],
  ]
);

/**
   +-----------+-------+---------+----------+--------------------------+
   | Name      | Value | Hash    | Tag      | Description              |
   |           |       |         | Length   |                          |
   +-----------+-------+---------+----------+--------------------------+
   | HMAC      | 4     | SHA-256 | 64       | HMAC w/ SHA-256          |
   | 256/64    |       |         |          | truncated to 64 bits     |
   | HMAC      | 5     | SHA-256 | 256      | HMAC w/ SHA-256          |
   | 256/256   |       |         |          |                          |
   | HMAC      | 6     | SHA-384 | 384      | HMAC w/ SHA-384          |
   | 384/384   |       |         |          |                          |
   | HMAC      | 7     | SHA-512 | 512      | HMAC w/ SHA-512          |
   | 512/512   |       |         |          |                          |
   +-----------+-------+---------+----------+--------------------------+
 */
export const macAlgs = new Map<number, { name: string, hash: string, length?: number }>([
  [5, { name: 'HS256', hash: 'SHA-256', length: 256 }]
]);

export const macAlgsToValue = new Map<string, number>(
  [
    ['HS256', 5],
  ]
);

export const algsToValue = new Map<string, number>(
  [
    ['EdDSA', -8],
    ['ES256', -7],
    ['ES384', -35],
    ['ES512', -36],
    ['PS256', -37],
    ['PS384', -38],
    ['PS512', -39],
    ['RS256', -257],
    ['RS384', -258],
    ['RS512', -259],
  ]
);

export const headers: { [k: string]: number } = {
  partyUNonce: -22,
  static_key_id: -3,
  static_key: -2,
  ephemeral_key: -1,
  alg: 1,
  crit: 2,
  ctyp: 3,
  kid: 4,
  IV: 5,
  Partial_IV: 6,
  counter_signature: 7,
  x5bag: 32,
  x5chain: 33,
  x5t: 34,
  x5u: 35,
};

export type ProtectedHeader = {
  alg?: 'EdDSA' | 'ES256' | 'ES384' | 'ES512' | 'PS256' | 'PS384' | 'PS512' | 'RS256' | 'RS384' | 'RS512',
  crit?: number[],
  ctyp?: number | string,
  [key: string]: unknown,
};

export type MacProtectedHeader = {
  alg?: 'HS256',
  crit?: number[],
  ctyp?: number | string,
  [key: string]: unknown,
};

export type UnprotectedHeaders = {
  ctyp?: number | string,
  kid?: Uint8Array | string,
  x5chain?: Uint8Array | Uint8Array[],
};

export const encodeProtectedHeaders = (protectedHeader: ProtectedHeader | undefined) => {
  if (typeof protectedHeader === 'undefined') {
    return new Uint8Array();
  }

  return encoder.encode(new Map(Object.entries(protectedHeader || {}).map(([k, v]: [string, unknown]) => {
    if (k === 'alg') {
      v = algsToValue.get(v as string);
    } else if (typeof v === 'string') {
      v = fromUTF8(v);
    }
    return [headers[k], v];
  })))
};

export const mapUnprotectedHeaders = (unprotectedHeader: UnprotectedHeaders | undefined) => {
  return new Map(Object.entries(unprotectedHeader || {}).map(([k, v]: [string, unknown]) => {
    if (typeof v === 'string') {
      v = fromUTF8(v);
    }
    return [headers[k], v];
  }));
};
