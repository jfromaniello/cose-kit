import { reverseMap } from '../util/maps.js';

export const ALG = new Map<number, string>(
  [
    [-8, 'EdDSA'],
    [-7, 'ES256'],
    [-35, 'ES384'],
    [-36, 'ES512'],
    [-37, 'PS256'],
    [-38, 'PS384'],
    [-39, 'PS512'],
    [-257, 'RS256'],
    [-258, 'RS384'],
    [-259, 'RS512'],
  ]
);

export const COSE_ALG = reverseMap(ALG);
