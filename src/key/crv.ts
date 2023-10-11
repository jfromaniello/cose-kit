import { reverseMap } from '../util/maps.js';

export const CURVE = new Map<number, string>([
  [1, 'P-256'],
  [2, 'P-384'],
  [3, 'P-521'],
  [4, 'X25519'],
  [5, 'X448'],
  [6, 'Ed25519'],
  [7, 'Ed448'],
]);

export const COSE_CURVE = reverseMap(CURVE);
