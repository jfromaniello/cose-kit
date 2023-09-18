import { Signature } from '../cose/Sign';
import { JSONWebKeySet, KeyLike } from 'jose';
// eslint-disable-next-line @typescript-eslint/ban-ts-comment
// @ts-ignore
import { LocalJWKSet } from 'jose/jwks/local';

export class COSELocalJWKSet<T extends KeyLike = KeyLike> extends LocalJWKSet<T> {
  constructor(jwks: JSONWebKeySet) {
    super(jwks);
  }

  async getKeyFromCOSESignature(signature: Signature): Promise<T> {
    return super.getKey({ alg: signature.algName, kid: signature.kid });
  }
}

export type COSEVerifyGetKey = ReturnType<typeof createLocalJWKSet>;

export function createLocalJWKSet<T extends KeyLike = KeyLike>(jwks: JSONWebKeySet) {
  const set = new COSELocalJWKSet<T>(jwks)
  return async function (
    signature: Signature
  ): Promise<T> {
    return set.getKeyFromCOSESignature(signature)
  }
}

