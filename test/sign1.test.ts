import * as fs from 'fs';
import { getPublicJWK } from './util.js';
import { KeyLike, importJWK } from 'jose';
import { Sign1, errors } from '../src/index.js';

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
    await expect(Sign1.decode(cose).verify(key))
      .rejects
      .toThrowErrorMatching(
        errors.COSESignatureVerificationFailed,
        'signature verification failed'
      );
  };

const verifies =
  async (cose: Uint8Array, key: Uint8Array | KeyLike, externalAAD?: Uint8Array): Promise<void> => {
    await Sign1.decode(cose).verify(key, { externalAAD });
  };

describe('sign1-tests', () => {
  testExample(
    'sign-fail-01.json',
    'should fail',
    async (cose) => {
      return expect(() => Sign1.decode(cose))
        .toThrow('Unexpected CBOR tag. Expected tag 18 (Sign1) but got 998');
    });

  testExample(
    'sign-fail-02.json',
    'should fail',
    notVerify);

  testExample(
    'sign-fail-03.json',
    'should fail',
    async (cose, key) => {
      await expect(Sign1.decode(cose).verify(key))
        .rejects
        .toThrowErrorMatching(
          errors.COSEInvalid,
          'Unsupported algorithm -999'
        );
    });

  testExample(
    'sign-fail-04.json',
    'should fail',
    async (cose, key) => {
      await expect(Sign1.decode(cose).verify(key))
        .rejects
        .toThrowErrorMatching(
          errors.COSEInvalid,
          'Unsupported algorithm unknown'
        );
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



