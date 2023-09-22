import * as fs from 'fs';
import { encoder } from '../../src/cbor.js';
import { Signature } from '../../src/cose/Sign.js';

describe('signature', () => {
  const example = JSON.parse(fs.readFileSync('./test/Examples/sign-tests/sign-pass-03.json', 'utf8'));
  const cose = Buffer.from(example.output.cbor, 'hex');
  const decoded = encoder.decode(cose);
  let signer: Signature;

  beforeAll(() => {
    signer = new Signature(...(decoded[3][0] as [Uint8Array, Map<number, unknown>, Uint8Array]));
  });

  it('should properly map kid', () => {
    expect(signer.kid).toEqual(decoded[3][0][1].get(4));
  });

  it('should properly map alg', () => {
    const expected = encoder.decode(decoded[3][0][0]).get(1);
    expect(typeof signer.alg)
      .toBe('number');
    expect(signer.alg)
      .toEqual(expected);
  });
});
