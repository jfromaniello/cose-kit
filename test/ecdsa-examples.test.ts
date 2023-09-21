import * as fs from 'fs';
import { getJWKSetFromExample } from './util';
import { coseVerify, coseVerifyMultiSignature, coseSign } from '../src';
import { importJWK } from 'jose';
const examples = [
  `${__dirname}/Examples/ecdsa-examples/ecdsa-sig-01.json`,
  `${__dirname}/Examples/ecdsa-examples/ecdsa-sig-02.json`,
  `${__dirname}/Examples/ecdsa-examples/ecdsa-sig-03.json`,

  // ECDSA - P-256 w/ SHA-512 - implicit not supported
  // `${__dirname}/Examples/ecdsa-examples/ecdsa-sig-04.json`,
  // `${__dirname}/Examples/ecdsa-examples/ecdsa-04.json`,

  `${__dirname}/Examples/ecdsa-examples/ecdsa-01.json`,
  `${__dirname}/Examples/ecdsa-examples/ecdsa-02.json`,
  `${__dirname}/Examples/ecdsa-examples/ecdsa-03.json`,
].map((examplePath) => JSON.parse(fs.readFileSync(examplePath, 'utf8')));

describe('ecdsa-examples', () => {

  examples.forEach(example => {

    describe(example.title, () => {
      it('should verify the signature', async () => {
        const key = getJWKSetFromExample(example);
        const verifyFunc = example.input.sign0 ? coseVerify : coseVerifyMultiSignature;
        const result = await verifyFunc(
          Buffer.from(example.output.cbor, 'hex'),
          key
        );
        expect(result.isValid).toBeTruthy();
        expect(result.decoded).toMatchSnapshot()
      });

      if (example.input.sign0) {
        it('can generate the signature as the example', async () => {
          const getPublicKey = getJWKSetFromExample(example);
          const verifyFunc = example.input.sign0 ? coseVerify : coseVerifyMultiSignature;
          const result = await verifyFunc(
            Buffer.from(example.output.cbor, 'hex'),
            getPublicKey
          );

          const key = await importJWK(example.input.sign0.key);
          const sign1 = await coseSign(
            example.input.sign0.protected,
            example.input.sign0.unprotected,
            Buffer.from(example.input.plaintext, 'utf8'),
            key
          );

          const result2 = await verifyFunc(sign1, getPublicKey);

          expect(result2.isValid).toBeTruthy();
          expect(result.isValid).toBeTruthy();

          expect(result2.decoded.protectedHeader)
            .toMatchObject(result.decoded.protectedHeader);
          expect(result2.decoded.unprotectedHeader)
            .toMatchObject(result.decoded.unprotectedHeader);
          expect(result2.decoded.payload)
            .toMatchObject(result.decoded.payload);
        });
      }

    });
  });

});
