import fs from 'fs';
import { getPublicJWK } from './util';
import { coseVerify } from '../src/verify';
import { KeyLike, importJWK } from 'jose';

const basePath = `${__dirname}/Examples/sign1-tests`;

const testExample = (
  filePath: string,
  testDescription: string,
  assert: (cose: Uint8Array, key: KeyLike | Uint8Array) => Promise<void>
) => {
  const example = JSON.parse(fs.readFileSync(`${basePath}/${filePath}`, 'utf8'));
  describe(example.title, () => {
    it(testDescription, async () => {
      const key = await importJWK(getPublicJWK(example.input.sign0.key));
      await assert(Buffer.from(example.output.cbor, 'hex'), key);
    });
  });
};

const notVerify =
  async (cose: Uint8Array, key: Uint8Array | KeyLike): Promise<void> => {
    const { isValid } = await coseVerify(cose, key);
    expect(isValid).toBeFalsy();
  };

describe('sign1-tests', () => {
  testExample(
    'sign-fail-01.json',
    'should fail',
    (cose, key) => {
      return expect(coseVerify(cose, key)).rejects.toThrow('unknown COSE type');
    });

  testExample(
    'sign-fail-02.json',
    'should fail',
    notVerify);

  testExample(
    'sign-fail-03.json',
    'should fail',
    async (cose, key) => {
      await expect(coseVerify(cose, key))
        .rejects.toThrow('unknown algorithm: -999');
    });

  testExample(
    'sign-fail-04.json',
    'should fail',
    async (cose, key) => {
      await expect(coseVerify(cose, key))
        .rejects.toThrow('unknown algorithm: unknown');
    });

  testExample(
    'sign-fail-06.json',
    'should not verify',
    notVerify);

  testExample(
    'sign-fail-07.json',
    'should not verify',
    notVerify);

  testExample(
    'sign-pass-01.json',
    'should not verify',
    notVerify);

  testExample(
    'sign-pass-02.json',
    'should not verify',
    notVerify);

  testExample(
    'sign-pass-03.json',
    'should not verify',
    (cose, key) => {
      return expect(coseVerify(cose, key)).rejects.toThrow('unknown COSE type');
    });
});



