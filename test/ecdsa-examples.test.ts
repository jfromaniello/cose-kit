import * as fs from 'fs';
import { getJWKSetFromExample, mapExampleProtectedHeaders } from './util.js';
import { Sign, Sign1 } from '../src/index.js';
import { JWK, importJWK } from 'jose';

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
      const SignatureClass = example.input.sign0 ? Sign1 : Sign;
      let verified = false;
      // let exampleSignatureVerificationResult: VerificationResult;
      let decoded: Sign1 | Sign;

      beforeAll(async () => {
        try {
          decoded = SignatureClass.decode(Buffer.from(example.output.cbor, 'hex'));
          await decoded.verify(getPublicKey);
          verified = true;
        } catch (e) {
          verified = false;
        }
      });

      it('should verify the example signature', async () => {
        expect(verified).toBeTruthy();
      });

      it('should properly decode the payload', () => {
        expect(decoded).toMatchSnapshot();
      })

      describe('when signing the example', () => {
        let signatureVerified = false;
        let decoded2: Sign1 | Sign;

        beforeAll(async () => {
          let signed: Uint8Array;
          if (example.input.sign0) {
            signed = await Sign1.sign(
              mapExampleProtectedHeaders(example.input.sign0.protected),
              mapExampleProtectedHeaders(example.input.sign0.unprotected),
              Buffer.from(example.input.plaintext, 'utf8'),
              await importJWK(example.input.sign0.key)
            ).then(s => s.encode());
          } else {
            const signers = await Promise.all(
              example.input.sign.signers.map(async (signer: { key: JWK; protected: unknown; unprotected: unknown; }) => {
                return {
                  key: await importJWK(signer.key),
                  protectedHeaders: mapExampleProtectedHeaders(signer.protected),
                  unprotectedHeaders: mapExampleProtectedHeaders(signer.unprotected),
                };
              }
              )
            );
            signed = await Sign.sign(
              mapExampleProtectedHeaders(example.input.sign.protected),
              mapExampleProtectedHeaders(example.input.sign.unprotected),
              Buffer.from(example.input.plaintext, 'utf8'),
              signers
            ).then(s => s.encode());
          }
          decoded2 = SignatureClass.decode(signed);
          await decoded2.verify(getPublicKey);
          signatureVerified = true;
        });

        it('should generate a valid signature', async () => {
          expect(signatureVerified).toBeTruthy();
        });

        it('should encode as the example', () => {
          if (decoded instanceof Sign) {
            expect((decoded2 as Sign).signatures.length)
              .toBe(decoded.signatures.length);
          }
          expect(decoded2.protectedHeaders)
            .toMatchObject(decoded.protectedHeaders);
          expect(decoded2.unprotectedHeaders)
            .toMatchObject(decoded.unprotectedHeaders);
          expect(decoded2.payload)
            .toMatchObject(decoded.payload);
        });
      });
    });
  });

});
