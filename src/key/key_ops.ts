export enum KeyOps {
  Sign = 1,
  Verify = 2,
  Encrypt = 3,
  Decrypt = 4,
  WrapKey = 5,
  UnwrapKey = 6,
  DeriveKey = 7,
  DeriveBits = 8,
  MACCreate = 9,
  MACVerify = 10,
}

export const JWKKeyOps = new Map<KeyOps, string>([
  [KeyOps.Sign, 'sign'],
  [KeyOps.Verify, 'verify'],
  [KeyOps.Encrypt, 'encrypt'],
  [KeyOps.Decrypt, 'decrypt'],
  [KeyOps.WrapKey, 'wrapKey'],
  [KeyOps.UnwrapKey, 'unwrapKey'],
  [KeyOps.DeriveKey, 'deriveKey'],
  [KeyOps.DeriveBits, 'deriveBits'],
  //in JWK MAC Create and MAC Verify are sign and verify.
  [KeyOps.MACCreate, 'sign'],
  [KeyOps.MACVerify, 'verify']
]);

export const JWKKeyOpsToCOSE = new Map<string, KeyOps[]>([
  ['sign', [KeyOps.Sign, KeyOps.MACCreate]],
  ['verify', [KeyOps.Verify, KeyOps.MACVerify]],
  ['encrypt', [KeyOps.Encrypt]],
  ['decrypt', [KeyOps.Decrypt]],
  ['wrapKey', [KeyOps.WrapKey]],
  ['unwrapKey', [KeyOps.UnwrapKey]],
  ['deriveKey', [KeyOps.DeriveKey]],
  ['deriveBits', [KeyOps.DeriveBits]],
]);
