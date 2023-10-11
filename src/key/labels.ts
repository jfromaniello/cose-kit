import { reverseMap } from "../util/maps.js";

export const LABEL = new Map([
  [1, 'kty'],
  [2, 'kid'],
  [3, 'alg'],
  [4, 'key_ops'],
  [5, 'base_iv'],
]);

export const KEY_TYPE_LABELS: { [k: string]: Map<number, string> | undefined } = {
  'EC': new Map([
    [-1, 'crv'],
    [-2, 'x'],
    [-3, 'y'],
    [-4, 'd'],
  ]),
  'OKP': new Map([
    [-1, 'crv'],
    [-2, 'x'],
    [-3, 'y'],
    [-4, 'd'],
  ]),
  'oct': new Map([
    [-1, 'k'],
  ]),
};

export const COSE_LABEL = reverseMap(LABEL);

export const COSE_KEY_TYPE_LABELS = Object.fromEntries(
  Object
    .entries(KEY_TYPE_LABELS)
    .map(([k, v]) => [k, reverseMap(v!)])
);

export const BufferTypes = [
  "base_iv",
  "d",
  "x",
  "y",
  "n",
  "e",
  "p",
  "q",
  "dp",
  "dq",
  "qi",
  "r_i",
  "d_i",
  "t_i",
  "k",
  "pub",
];
