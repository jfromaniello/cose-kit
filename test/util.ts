import { JWK } from "jose";
import { createLocalJWKSet } from "../src/jwks/local";

export const parseJWK = (jwk: object): JWK => {
  const result: JWK = {
    ...jwk,
  };
  Object.keys(result).filter(k => k.endsWith('_hex')).forEach(k => {
    result[k.replace('_hex', '')] = Buffer.from(result[k] as string, 'hex').toString('base64');
    delete result[k]
  });
  if (result.kty === 'EC2') {
    result.kty = 'EC';
  }
  return result;
};

export const getPublicJWK = (jwk: JWK): JWK => {
  // eslint-disable-next-line @typescript-eslint/no-unused-vars
  const { d, ...publicJWK } = parseJWK(jwk);
  return publicJWK;
};

/**
 * Builds a JWK keyset from an COSE example.
 *
 * @param example The COSE example
 * @returns ReturnType<typeof createLocalJWKSet>
 */
export const getJWKSetFromExample = (example: Example) => {
  if (typeof example.input.sign !== 'undefined') {
    return createLocalJWKSet({
      keys: example.input.sign.signers.map(signer => getPublicJWK(signer.key))
    });
  } else if (example.input.sign0?.key) {
    return createLocalJWKSet({
      keys: [getPublicJWK(example.input.sign0.key)]
    });
  } else {
    throw new Error('unkown example');
  }
};


// Types for https://github.com/cose-wg/Examples

export interface Example {
  title: string;
  input: Input;
  intermediates: Intermediates;
  output: Output;
}

export interface Input {
  plaintext: string;
  sign0?: Signer;
  sign?: { signers: Signer[] };
  rng_description: string;
}

export interface Signer {
  key: JWK;
  unprotected: Unprotected;
  protected: Protected;
  alg: string;
}

export interface Protected {
  alg: string;
  ctyp: number;
}

export interface Unprotected {
  kid: string;
}

export interface Intermediates {
  ToBeSign_hex: string;
}

export interface Output {
  cbor_diag: string;
  cbor: string;
}
