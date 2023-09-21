import * as fs from 'fs';
import { coseVerifyX509 } from '../src/verify';

const examples = [
  `${__dirname}/Examples/x509-examples/signed-03.json`,

].map((examplePath) => JSON.parse(fs.readFileSync(examplePath, 'utf8')));

describe('x509-examples', () => {

  examples.forEach(example => {

    describe(example.title, () => {
      it('should verify the signature', async () => {
        // test/Examples/x509-examples/alice.crt
        const ca = fs.readFileSync(`${__dirname}/Examples/x509-examples/ca.crt`, 'utf8')
        // const cert = await importX509(x509, 'ES256');
        // console.dir(cert);
        // const key = getJWKSetFromExample(example);
        const result = await coseVerifyX509(
          Buffer.from(example.output.cbor, 'hex'),
          [ca]
        );
        expect(result.isValid).toBeTruthy();
      });
    });

  });

});
