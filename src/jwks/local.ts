import { JSONWebKeySet, KeyLike } from 'jose';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { LocalJWKSet } from 'jose/jwks/local';
import { SignatureBase } from '../cose/SignatureBase';

export class COSELocalJWKSet<T extends KeyLike = KeyLike> extends LocalJWKSet<T> {
  constructor(jwks: JSONWebKeySet) {
    super(jwks);
  }

  async getKeyFromCOSESignature(signature: SignatureBase): Promise<T> {
    return super.getKey({ alg: signature.algName, kid: signature.kid });
  }
}

export type COSEVerifyGetKey = ReturnType<typeof createLocalJWKSet>;

export function createLocalJWKSet<T extends KeyLike = KeyLike>(jwks: JSONWebKeySet) {
  const set = new COSELocalJWKSet<T>(jwks)
  return async function (
    signature: SignatureBase
  ): Promise<T> {
    return set.getKeyFromCOSESignature(signature)
  }
}

