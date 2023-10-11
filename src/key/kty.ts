import { reverseMap } from '../util/maps.js';

export const KEY_TYPE = new Map([
  [1, 'OKP'],
  [2, 'EC'],
  [4, 'oct'],
  [0, 'Reserved'],
]);

export const COSE_KEY_TYPE = reverseMap(KEY_TYPE);
