import * as fs from 'fs';
import crypto from 'crypto';

import { Sign, Sign1 } from '../src/index.js';
import { JWK, importJWK } from 'jose';
import { mapExampleProtectedHeaders, parseJWK } from './util.js';
import { Algorithms, Headers, ProtectedHeaders, UnprotectedHeaders } from '../src/headers.js';

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
        const decoded = example.input.sign0 ?
          Sign1.decode(Buffer.from(example.output.cbor, 'hex')) :
          Sign.decode(Buffer.from(example.output.cbor, 'hex'));
        await decoded.verifyX509(
          caRoots
        );
      });

      describe('when signing a certificate with x5chain', () => {
        let decoded: Sign1 | Sign;

        beforeAll(async () => {
          let signed: Uint8Array;
          if (example.input.sign0) {
            signed = await Sign1.sign(
              mapExampleProtectedHeaders(example.input.sign0.protected),
              mapExampleProtectedHeaders(example.input.sign0.unprotected),
              Buffer.from(example.input.plaintext, 'utf8'),
              await importJWK(parseJWK(example.input.sign0.key))
            ).then(s => s.encode());
            decoded = Sign1.decode(signed);
          } else {
            const signers = await Promise.all(
              example.input.sign.signers.map(async (signer: { key: JWK; protected: unknown; unprotected: { x5chain?: string }; }) => {
                return {
                  key: await importJWK(parseJWK(signer.key)),
                  // @ts-ignore
                  protectedHeaders: mapExampleProtectedHeaders(signer.protected),
                  unprotectedHeaders: mapExampleProtectedHeaders({
                    ...signer.unprotected || {},
                    x5chain: signer.unprotected?.x5chain ? Buffer.from(signer.unprotected?.x5chain, 'hex') : undefined
                  }),
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
            decoded = Sign.decode(signed);
          }
          decoded.verifyX509(caRoots);
        });

        it('should contain the x5chain', () => {
          const current = ((decoded as Sign)
            .signatures[0]
            .unprotectedHeaders
            .get(Headers.X5Chain) as Buffer).toString('hex').toUpperCase();
          const expected = example.input.sign0?.unprotected?.x5chain ||
            example.input.sign?.signers[0].unprotected.x5chain;
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
      const signed = await Sign1.sign(
        new ProtectedHeaders([[Headers.Algorithm, Algorithms.ES256]]),
        new UnprotectedHeaders([[
          Headers.X5Chain, x5chain
        ]]),
        payload,
        key
      );

      await expect(signed.verifyX509(caRoots))
        .rejects
        .toThrowErrorMatchingSnapshot();
    });
  });
});
