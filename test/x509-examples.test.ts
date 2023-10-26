import * as fs from 'fs';
import crypto from 'crypto';

import { coseVerifyX509 } from '../src/verify.js';
import { Sign, coseMultiSign, coseSign } from '../src/index.js';
import { JWK, importJWK } from 'jose';
import { parseJWK } from './util.js';
import { headers } from '../src/headers.js';

const caRoots = [
  fs.readFileSync(`${__dirname}/Examples/x509-examples/ca.crt`, 'utf8')
];

const examples = [
  `${__dirname}/Examples/x509-examples/signed-03.json`,

].map((examplePath) => JSON.parse(fs.readFileSync(examplePath, 'utf8')));

describe('x509-examples', () => {

  examples.forEach(example => {

    describe(example.title, () => {

      it('should verify the signature', async () => {
        const result = await coseVerifyX509(
          Buffer.from(example.output.cbor, 'hex'),
          caRoots
        );
        expect(result.isValid).toBeTruthy();
      });

      describe('when signing a certificate with x5chain', () => {
        let signatureVerificationResult: Awaited<ReturnType<typeof coseVerifyX509>>;

        beforeAll(async () => {
          let signed: Uint8Array;
          if (example.input.sign0) {
            signed = await coseSign(
              example.input.sign0.protected,
              example.input.sign0.unprotected,
              Buffer.from(example.input.plaintext, 'utf8'),
              await importJWK(parseJWK(example.input.sign0.key))
            );
          } else {
            const signers = await Promise.all(
              example.input.sign.signers.map(async (signer: { key: JWK; protected: unknown; unprotected: { x5chain?: string }; }) => {
                return {
                  key: await importJWK(parseJWK(signer.key)),
                  protectedHeaders: signer.protected,
                  unprotectedHeaders: {
                    ...signer.unprotected || {},
                    x5chain: signer.unprotected?.x5chain ? Buffer.from(signer.unprotected?.x5chain, 'hex') : undefined
                  },
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
          signatureVerificationResult = await coseVerifyX509(signed, caRoots);
        });

        it('should verify the signature', async () => {
          expect(signatureVerificationResult.isValid).toBeTruthy();
        });

        it('should contain the x5chain', () => {
          const current = ((signatureVerificationResult.decoded as Sign)
            .signatures[0]
            .unprotectedHeaders
            .get(headers.x5chain) as Buffer).toString('hex').toUpperCase();
          const expected = example.input.sign0?.unprotected?.x5chain || example.input.sign?.signers[0].unprotected.x5chain;
          expect(current).toBe(expected);
        });

      });
    });

  });

  describe('sign with an expired cert in x5chain', () => {
    const key = crypto.createPrivateKey(fs.readFileSync(`${__dirname}/Examples/x509-examples/expired.key`, 'utf8'));
    const x5chain = fs.readFileSync(`${__dirname}/Examples/x509-examples/expired.der`);
    const payload = Buffer.from('Hello World!');
    it('should fail to verify', async () => {
      const signed = await coseSign(
        { alg: 'ES256' },
        { x5chain },
        payload,
        key
      );
      await expect(coseVerifyX509(signed, caRoots))
        .rejects
        .toThrowErrorMatchingSnapshot();
    });
  });
});
