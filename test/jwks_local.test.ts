import example from './Examples/sign-tests/sign-pass-03.json';
import { createLocalJWKSet } from '../src/jwks/local';
import { Signature } from '../src/cose/Sign';
import { encoder } from '../src/cbor';
import { getJWKSetFromExample, getPublicJWK } from './util';
import { coseVerify } from '../src/verify';
import ecdsaSig01 from './Examples/ecdsa-examples/ecdsa-sig-01.json';

describe('jwks_local', () => {
  const getKey = createLocalJWKSet({
    keys: example.input.sign.signers.map((signer) => getPublicJWK(signer.key))
  });
  const cose = Buffer.from(example.output.cbor, 'hex');
  const decoded = encoder.decode(cose);
  const signature = new Signature(...(decoded[3][0] as [Uint8Array, Map<number, unknown>, Uint8Array]));

  it('should find the key', async () => {
    const key = await getKey(signature);
    expect(key).toBeTruthy();
  });

  it('should verify the signature when using the createLocalJWKSet', async () => {
    const getKey = getJWKSetFromExample(ecdsaSig01);
    const result = await coseVerify(
      Buffer.from(ecdsaSig01.output.cbor, 'hex'),
      getKey
    );
    expect(result.isValid).toBeTruthy();
  });
});
