import * as fs from 'fs';
import { getPublicJWK } from './util.js';
// import { coseVerify } from '../src/verify';
import { importJWK } from 'jose';
import { Sign1 } from '../src/index.js';

const examples = [
  `${__dirname}/Examples/eddsa-examples/eddsa-sig-01.json`,
  `${__dirname}/Examples/eddsa-examples/eddsa-sig-02.json`,
].map((examplePath) => JSON.parse(fs.readFileSync(examplePath, 'utf8')));

describe('eddsa-examples', () => {
  examples.forEach(example => {
    describe(example.title, () => {
      it('should verify the signature', async () => {
        const key = await importJWK(getPublicJWK(example.input.sign0.key));
        const decoded = Sign1.decode(Buffer.from(example.output.cbor, 'hex'));
        await decoded.verify(
          key
        );
      });
    });
  });
});
