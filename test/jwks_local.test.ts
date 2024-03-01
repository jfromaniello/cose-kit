import example from './Examples/sign-tests/sign-pass-03.json';
import { createLocalJWKSet } from '../src/jwks/local.js';
import { Signature } from '../src/cose/Sign.js';
import { encoder } from '../src/cbor.js';
import { getJWKSetFromExample, getPublicJWK } from './util.js';
import ecdsaSig01 from './Examples/ecdsa-examples/ecdsa-sig-01.json';
import { Sign1 } from '../src/index.js';

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
    const decoded = Sign1.decode(Buffer.from(ecdsaSig01.output.cbor, 'hex'));
    await decoded.verify(
      getKey
    );
  });
});
