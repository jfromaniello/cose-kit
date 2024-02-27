import * as fs from 'fs';
import { getPublicJWK } from './util.js';
import { coseVerify } from '../src/verify.js';
import { KeyLike, importJWK } from 'jose';

const basePath = `${__dirname}/Examples/sign1-tests`;

const testExample = (
  filePath: string,
  testDescription: string,
  assert: (cose: Uint8Array, key: KeyLike | Uint8Array, externalAAD?: Uint8Array) => Promise<void>
) => {
  const example = JSON.parse(fs.readFileSync(`${basePath}/${filePath}`, 'utf8'));
  describe(example.title, () => {
    it(testDescription, async () => {
      const key = await importJWK(getPublicJWK(example.input.sign0.key));
      const cose = Buffer.from(example.output.cbor, 'hex');
      const externalAAD = example.input.sign0.external ?
        Buffer.from(example.input.sign0.external, 'hex') :
        new Uint8Array();

      await assert(cose, key, externalAAD);
    });
  });
};

const notVerify =
  async (cose: Uint8Array, key: Uint8Array | KeyLike): Promise<void> => {
    const { isValid } = await coseVerify(cose, key);
    expect(isValid).toBeFalsy();
  };

const verifies =
  async (cose: Uint8Array, key: Uint8Array | KeyLike, externalAAD?: Uint8Array): Promise<void> => {
    const { isValid } = await coseVerify(cose, key, externalAAD);
    expect(isValid).toBeTruthy();
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
    'should verify',
    verifies);

  testExample(
    'sign-pass-03.json',
    'should verify',
    verifies);
});



