import * as fs from 'fs';
import { getJWKSetFromExample } from './util.js';
import { coseVerify, coseVerifyMultiSignature, coseSign, coseMultiSign, Sign } from '../src/index.js';
import { JWK, importJWK } from 'jose';
type VerificationResult = Awaited<ReturnType<typeof coseVerify> | ReturnType<typeof coseVerifyMultiSignature>>;

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
      const getPublicKey = getJWKSetFromExample(example);
      const verifyFunc = example.input.sign0 ? coseVerify : coseVerifyMultiSignature;
      let exampleSignatureVerificationResult: VerificationResult;

      beforeAll(async () => {
        exampleSignatureVerificationResult = await verifyFunc(
          Buffer.from(example.output.cbor, 'hex'),
          getPublicKey
        );
      });

      it('should verify the example signature', async () => {
        expect(exampleSignatureVerificationResult.isValid).toBeTruthy();
      });

      it('should properly decode the payload', () => {
        expect(exampleSignatureVerificationResult.decoded).toMatchSnapshot();
      })

      describe('when signing the example', () => {
        let signatureVerificationResult: VerificationResult;

        beforeAll(async () => {
          let signed: Uint8Array;
          if (example.input.sign0) {
            signed = await coseSign(
              example.input.sign0.protected,
              example.input.sign0.unprotected,
              Buffer.from(example.input.plaintext, 'utf8'),
              await importJWK(example.input.sign0.key)
            );
          } else {
            const signers = await Promise.all(
              example.input.sign.signers.map(async (signer: { key: JWK; protected: unknown; unprotected: unknown; }) => {
                return {
                  key: await importJWK(signer.key),
                  protectedHeaders: signer.protected,
                  unprotectedHeaders: signer.unprotected,
                };
              }
              )
            );
            signed = await coseMultiSign(
              example.input.sign.protected,
              example.input.sign.unprotected,
              Buffer.from(example.input.plaintext, 'utf8'),
              signers
            );
          }
          signatureVerificationResult = await verifyFunc(signed, getPublicKey);
        });

        it('should generate a valid signature', async () => {
          expect(signatureVerificationResult.isValid).toBeTruthy();
        });

        it('should encode as the example', () => {
          if (exampleSignatureVerificationResult.decoded instanceof Sign) {
            expect((signatureVerificationResult.decoded as Sign).signatures.length)
              .toBe(exampleSignatureVerificationResult.decoded.signatures.length);
          }
          expect(signatureVerificationResult.decoded.protectedHeaders)
            .toMatchObject(exampleSignatureVerificationResult.decoded.protectedHeaders);
          expect(signatureVerificationResult.decoded.unprotectedHeaders)
            .toMatchObject(exampleSignatureVerificationResult.decoded.unprotectedHeaders);
          expect(signatureVerificationResult.decoded.payload)
            .toMatchObject(exampleSignatureVerificationResult.decoded.payload);
        });
      });
    });
  });

});
