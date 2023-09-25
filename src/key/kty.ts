export enum KeyType {
  // Octet Key Pair
  OKP = 1,

  // Elliptic Curve Keys w/ x- and y-coordinate pair
  EC2 = 2,

  // Symmetric Keys
  Symmetric = 4,

  // This value is reserved
  Reserved = 0,
}


export const ValueToKeyType = new Map([
  [1, 'OKP'],
  [2, 'EC'],
  [4, 'Symmetric'],
  [0, 'Reserved'],
]);
