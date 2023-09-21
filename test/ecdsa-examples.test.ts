import * as fs from 'fs';
import { getJWKSetFromExample } from './util';
import { coseVerify, coseVerifyMultiSignature } from '../src/verify';

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
    });

  });

});
