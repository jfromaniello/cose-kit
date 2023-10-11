import { reverseMap } from '../util/maps.js';

export const KEY_OPS = new Map([
  [1, 'sign'],
  [2, 'verify'],
  [3, 'encrypt'],
  [4, 'decrypt'],
  [5, 'wrapKey'],
  [6, 'unwrapKey'],
  [7, 'deriveKey'],
  [8, 'deriveBits'],
  //in JWK MAC Create and MAC Verify are sign and verify.
  [9, 'sign'],
  [10, 'verify']
]);

export const COSE_KEY_OPS = reverseMap(KEY_OPS);
