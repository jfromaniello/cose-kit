export enum KeyType {
  OKP = 1,
  EC = 2,
  OCT = 4,
  Reserved = 0,
}

export enum JWKKeyType {
  OKP = KeyType.OKP,
  EC = KeyType.EC,
  oct = KeyType.OCT,
}
