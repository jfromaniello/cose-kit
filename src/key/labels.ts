export enum Label {
  kty = 1,
  kid = 2,
  alg = 3,
  key_opts = 4,
  base_iv = 5,

  crv = -1,
  x = -2,
  y = -3,
  d = -4,
}

export const ValueToLabel = new Map([
  [1, 'kty'],
  [2, 'kid'],
  [3, 'alg'],
  [4, 'key_opts'],
  [5, 'base_iv'],
  [-1, 'crv'],
  [-2, 'x'],
  [-3, 'y'],
  [-4, 'd']
]);
